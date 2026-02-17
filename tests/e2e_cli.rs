#[cfg(target_os = "linux")]
mod linux_e2e {
    use nix::pty::openpty;
    use nix::sys::signal::{Signal, kill};
    use nix::sys::termios::{Termios, tcgetattr};
    use nix::unistd::Pid;
    use serde::Deserialize;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(test_name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "wsx-e2e-{test_name}-{}-{nanos}",
                std::process::id()
            ));

            fs::create_dir_all(&path).expect("failed to create temp root");
            Self { path }
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct TestEnv {
        _guard: TempDirGuard,
        home_dir: PathBuf,
        workspace_root: PathBuf,
    }

    impl TestEnv {
        fn new(test_name: &str) -> Self {
            let guard = TempDirGuard::new(test_name);
            let home_dir = guard.path.join("home");
            let workspace_root = guard.path.join("workspaces");

            fs::create_dir_all(home_dir.join(".config").join("wsx"))
                .expect("failed to create wsx config directory");
            fs::create_dir_all(&workspace_root).expect("failed to create workspace root");

            Self {
                _guard: guard,
                home_dir,
                workspace_root,
            }
        }

        fn create_workspace(&self, name: &str) -> PathBuf {
            let path = self.workspace_root.join(name);
            fs::create_dir_all(&path).expect("failed to create workspace path");
            path
        }

        fn write_config(&self, yaml: &str) {
            let config_path = self
                .home_dir
                .join(".config")
                .join("wsx")
                .join("config.yaml");
            fs::write(config_path, yaml).expect("failed to write config.yaml");
        }

        fn run(&self, args: &[&str]) -> Output {
            self.run_with_env(args, &[])
        }

        fn run_with_env(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
            self.build_command(args, extra_env)
                .output()
                .expect("failed to execute wsx")
        }

        fn spawn_with_pty(&self, args: &[&str], extra_env: &[(&str, &str)]) -> PtySession {
            PtySession::spawn(self, args, extra_env)
        }

        fn build_command(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Command {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_wsx"));
            cmd.args(args)
                .env("HOME", &self.home_dir)
                .env_remove("WSX_HOME");
            for (key, value) in extra_env {
                cmd.env(key, value);
            }
            cmd
        }

        fn wsx_home(&self) -> PathBuf {
            self.home_dir.join(".config").join("wsx")
        }
    }

    struct PtySession {
        child: Child,
        master: File,
        initial_termios: Termios,
    }

    impl PtySession {
        fn spawn(env: &TestEnv, args: &[&str], extra_env: &[(&str, &str)]) -> Self {
            let pty = openpty(None, None).expect("failed to create pty");
            let initial_termios = tcgetattr(&pty.master).expect("failed to read initial termios");

            let master = File::from(pty.master);
            let slave = File::from(pty.slave);
            let slave_in = slave
                .try_clone()
                .expect("failed to clone pty slave for stdin");
            let slave_out = slave
                .try_clone()
                .expect("failed to clone pty slave for stdout");

            let mut cmd = env.build_command(args, extra_env);
            cmd.stdin(Stdio::from(slave_in))
                .stdout(Stdio::from(slave_out))
                .stderr(Stdio::from(slave));

            let child = cmd.spawn().expect("failed to spawn wsx with pty");

            Self {
                child,
                master,
                initial_termios,
            }
        }

        fn write_bytes(&mut self, bytes: &[u8]) {
            self.master
                .write_all(bytes)
                .expect("failed to write to pty");
            self.master.flush().expect("failed to flush pty write");
        }

        fn wait_for_exit(&mut self, timeout: Duration) -> ExitStatus {
            let deadline = Instant::now() + timeout;
            loop {
                if let Some(status) = self.child.try_wait().expect("failed to poll wsx process") {
                    return status;
                }

                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for wsx process to exit"
                );
                thread::sleep(Duration::from_millis(25));
            }
        }

        fn send_sigint(&self) {
            let raw_pid = i32::try_from(self.child.id()).expect("child pid should fit i32");
            kill(Pid::from_raw(raw_pid), Signal::SIGINT).expect("failed to send SIGINT to wsx");
        }

        fn assert_terminal_restored(&self) {
            let current = tcgetattr(self.master.as_fd()).expect("failed to read current termios");
            assert_eq!(
                current.input_flags, self.initial_termios.input_flags,
                "input flags should be restored after wsx exits"
            );
            assert_eq!(
                current.output_flags, self.initial_termios.output_flags,
                "output flags should be restored after wsx exits"
            );
            assert_eq!(
                current.local_flags, self.initial_termios.local_flags,
                "local flags should be restored after wsx exits"
            );
        }
    }

    impl Drop for PtySession {
        fn drop(&mut self) {
            if self
                .child
                .try_wait()
                .expect("failed to poll wsx process")
                .is_none()
            {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    fn yaml_path(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "''"))
    }

    fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).to_string()
    }

    fn assert_success(output: &Output) {
        assert!(
            output.status.success(),
            "expected success, exit={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout(output),
            stderr(output)
        );
    }

    fn assert_failure(output: &Output) {
        assert!(
            !output.status.success(),
            "expected failure, but succeeded\nstdout:\n{}\nstderr:\n{}",
            stdout(output),
            stderr(output)
        );
    }

    fn assert_down_succeeded_message(output: &Output, workspace: &str) {
        let out = stdout(output);
        assert!(
            out.contains(&format!("stopped workspace `{workspace}`"))
                || out.contains(&format!("workspace `{workspace}` is already stopped")),
            "down output should indicate workspace stop state\nstdout:\n{}\nstderr:\n{}",
            out,
            stderr(output)
        );
    }

    fn assert_stdout_contains_all(output: &Output, expected: &[&str]) {
        let out = stdout(output);
        for item in expected {
            assert!(
                out.contains(item),
                "stdout should contain `{item}`\nstdout:\n{}\nstderr:\n{}",
                out,
                stderr(output)
            );
        }
    }

    fn assert_stderr_contains(output: &Output, expected: &str) {
        let err = stderr(output);
        assert!(
            err.contains(expected),
            "stderr should contain `{expected}`\nstdout:\n{}\nstderr:\n{}",
            stdout(output),
            err
        );
    }

    #[derive(Debug, Deserialize)]
    struct PidsMeta {
        workspace: String,
        entries: Vec<PidEntryMeta>,
    }

    #[derive(Debug, Deserialize)]
    struct PidEntryMeta {
        name: String,
        pid: u32,
    }

    #[derive(Debug, Deserialize)]
    struct CurrentMeta {
        instance_id: String,
        status: Option<String>,
    }

    fn workspace_instance_ids(env: &TestEnv, workspace_name: &str) -> Vec<String> {
        let instances_dir = env.wsx_home().join("instances");
        if !instances_dir.exists() {
            return vec![];
        }

        let mut out = Vec::new();
        for entry in fs::read_dir(&instances_dir).expect("failed to read instances dir") {
            let entry = entry.expect("failed to read instances entry");
            if !entry
                .file_type()
                .expect("failed to read file type")
                .is_dir()
            {
                continue;
            }

            let instance_id = entry.file_name().to_string_lossy().to_string();
            let pids_path = entry.path().join("pids.json");
            if !pids_path.exists() {
                continue;
            }

            let raw = fs::read_to_string(&pids_path).expect("failed to read pids file");
            let Ok(meta) = serde_json::from_str::<PidsMeta>(&raw) else {
                continue;
            };
            if meta.workspace == workspace_name {
                out.push(instance_id);
            }
        }

        out.sort();
        out
    }

    fn current_instance_id(env: &TestEnv) -> Option<String> {
        let current_path = env.wsx_home().join("current.json");
        if !current_path.exists() {
            return None;
        }

        let raw = fs::read_to_string(current_path).expect("failed to read current.json");
        let current: CurrentMeta = serde_json::from_str(&raw).expect("invalid current.json");
        Some(current.instance_id)
    }

    fn current_meta(env: &TestEnv) -> Option<CurrentMeta> {
        let current_path = env.wsx_home().join("current.json");
        if !current_path.exists() {
            return None;
        }

        let raw = fs::read_to_string(current_path).expect("failed to read current.json");
        let current: CurrentMeta = serde_json::from_str(&raw).expect("invalid current.json");
        Some(current)
    }

    fn current_process_pid(env: &TestEnv, process_name: &str) -> Option<u32> {
        let instance_id = current_instance_id(env)?;
        let pids_path = env
            .wsx_home()
            .join("instances")
            .join(instance_id)
            .join("pids.json");
        if !pids_path.exists() {
            return None;
        }

        let raw = fs::read_to_string(pids_path).expect("failed to read pids.json");
        let meta: PidsMeta = serde_json::from_str(&raw).expect("invalid pids.json");
        meta.entries
            .iter()
            .find(|entry| entry.name == process_name)
            .map(|entry| entry.pid)
    }

    fn wait_for_current_status(env: &TestEnv, expected: &str, timeout: Duration) -> bool {
        wait_until(timeout, || {
            current_meta(env).is_some_and(|meta| meta.status.as_deref() == Some(expected))
        })
    }

    fn wait_until(timeout: Duration, condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        condition()
    }

    fn pid_exists(pid: u32) -> bool {
        Path::new("/proc").join(pid.to_string()).exists()
    }

    #[test]
    fn list_shows_sorted_and_marks_current_workspace() {
        let env = TestEnv::new("list");
        let zeta = env.create_workspace("zeta");
        let alpha = env.create_workspace("alpha");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  zeta:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo zeta; sleep 1"]
  alpha:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo alpha; sleep 1"]
"#,
            yaml_path(&zeta),
            yaml_path(&alpha),
        ));

        let list_before = env.run(&["list"]);
        assert_success(&list_before);
        let before_stdout = stdout(&list_before);
        assert!(before_stdout.contains("  alpha"));
        assert!(before_stdout.contains("  zeta"));

        let alpha_index = before_stdout.find("alpha").expect("alpha should be listed");
        let zeta_index = before_stdout.find("zeta").expect("zeta should be listed");
        assert!(alpha_index < zeta_index, "workspaces should be sorted");

        let switch_alpha = env.run(&["alpha"]);
        assert_success(&switch_alpha);

        let list_after = env.run(&["list"]);
        assert_success(&list_after);
        let after_stdout = stdout(&list_after);
        assert!(after_stdout.contains("* alpha"));
        assert!(after_stdout.contains("  zeta"));
    }

    #[test]
    fn down_without_current_prints_no_current_workspace() {
        let env = TestEnv::new("down-no-current");
        let down = env.run(&["down"]);
        assert_success(&down);
        assert_stdout_contains_all(&down, &["no current workspace"]);
    }

    #[test]
    fn workspace_and_subcommand_together_fails() {
        let env = TestEnv::new("workspace-and-subcommand");
        let result = env.run(&["list", "demo"]);
        assert_failure(&result);
        assert_stderr_contains(&result, "unexpected argument");
    }

    #[test]
    fn up_without_current_fails() {
        let env = TestEnv::new("up-no-current");
        let up = env.run(&["up"]);
        assert_failure(&up);
        assert_stderr_contains(&up, "no current workspace");
    }

    #[test]
    fn logs_without_current_fails() {
        let env = TestEnv::new("logs-no-current");
        let logs = env.run(&["logs", "--no-follow"]);
        assert_failure(&logs);
        assert_stderr_contains(&logs, "no current workspace");
    }

    #[test]
    fn exec_without_current_fails() {
        let env = TestEnv::new("exec-no-current");
        let exec = env.run(&["exec", "sh", "-c", "echo hello"]);
        assert_failure(&exec);
        assert_stderr_contains(&exec, "no current workspace");
    }

    #[test]
    fn config_missing_file_returns_error() {
        let env = TestEnv::new("config-missing");
        let list = env.run(&["list"]);
        assert_failure(&list);
        assert_stderr_contains(&list, "config file not found");
    }

    #[test]
    fn config_with_empty_workspaces_returns_error() {
        let env = TestEnv::new("config-empty-workspaces");
        env.write_config(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces: {}
"#,
        );

        let list = env.run(&["list"]);
        assert_failure(&list);
        assert_stderr_contains(&list, "workspaces is empty");
    }

    #[test]
    fn workspace_with_no_processes_fails() {
        let env = TestEnv::new("workspace-no-processes");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes: []
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_failure(&switch);
        assert_stderr_contains(&switch, "has no processes");
    }

    #[test]
    fn switch_status_and_down_happy_path() {
        let env = TestEnv::new("lifecycle");
        let deva = env.create_workspace("deva");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  deva:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo app-out; echo app-err 1>&2; sleep 1"]
"#,
            yaml_path(&deva),
        ));

        let switch = env.run(&["deva"]);
        assert_success(&switch);
        let switch_stdout = stdout(&switch);
        assert!(switch_stdout.contains("switched to workspace `deva`"));

        let status = env.run(&["status"]);
        assert_success(&status);
        let status_stdout = stdout(&status);
        assert!(status_stdout.contains("Current workspace: deva"));
        assert!(status_stdout.contains("- app (pid "));

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "deva");

        let status_after_down = env.run(&["status"]);
        assert_success(&status_after_down);
        let status_after_down_stdout = stdout(&status_after_down);
        assert!(status_after_down_stdout.contains("Current workspace: deva"));
        assert!(status_after_down_stdout.contains("State: stopped"));
    }

    #[test]
    fn down_and_up_restart_current_workspace() {
        let env = TestEnv::new("down-up");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo demo-run; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let first_switch = env.run(&["demo"]);
        assert_success(&first_switch);
        let first_instance =
            current_instance_id(&env).expect("current instance should exist after first switch");

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");

        let meta_after_down = current_meta(&env).expect("current should be preserved after down");
        assert_eq!(meta_after_down.status.as_deref(), Some("stopped"));

        let up = env.run(&["up"]);
        assert_success(&up);
        assert!(stdout(&up).contains("started workspace `demo`"));

        let meta_after_up = current_meta(&env).expect("current should exist after up");
        assert_eq!(meta_after_up.status.as_deref(), Some("running"));
        assert_ne!(
            meta_after_up.instance_id, first_instance,
            "up should create a new instance id"
        );
    }

    #[test]
    fn switch_then_up_reports_already_running() {
        let env = TestEnv::new("up-already-running");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: short
        default_log: true
        cmd: ["sh", "-lc", "echo short; sleep 1"]
      - name: long
        cmd: ["sh", "-lc", "sleep 60"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let up = env.run(&["up"]);
        assert_success(&up);
        assert_stdout_contains_all(&up, &["workspace `demo` is already running"]);

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");
    }

    #[test]
    fn list_marks_current_after_down() {
        let env = TestEnv::new("list-after-down");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo boot; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");

        let list = env.run(&["list"]);
        assert_success(&list);
        assert_stdout_contains_all(&list, &["* demo"]);
    }

    #[test]
    fn status_reconciles_current_state_when_processes_already_stopped() {
        let env = TestEnv::new("status-reconcile");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo demo-run; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let before_status = current_meta(&env).expect("current should exist after switch");
        assert_eq!(
            before_status.status.as_deref(),
            Some("running"),
            "legacy/current behavior stores running after switch"
        );

        let status = env.run(&["status"]);
        assert_success(&status);
        assert!(stdout(&status).contains("State: stopped"));

        let after_status = current_meta(&env).expect("current should exist after status");
        assert_eq!(
            after_status.status.as_deref(),
            Some("stopped"),
            "status should reconcile current state to stopped"
        );
    }

    #[test]
    fn up_restarts_when_current_processes_already_stopped() {
        let env = TestEnv::new("up-restarts-stale-running");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo demo-run; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let first_switch = env.run(&["demo"]);
        assert_success(&first_switch);
        let first_instance =
            current_instance_id(&env).expect("current instance should exist after first switch");

        let up = env.run(&["up"]);
        assert_success(&up);
        assert!(
            stdout(&up).contains("started workspace `demo`"),
            "up should restart after reconciling stale running state"
        );

        let meta_after_up = current_meta(&env).expect("current should exist after up");
        assert_ne!(
            meta_after_up.instance_id, first_instance,
            "up should create a new instance id when previous processes are stopped"
        );
    }

    #[test]
    fn logs_default_and_explicit_stream_work() {
        let env = TestEnv::new("logs");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: backend
        default_log: true
        default_stream: err
        cmd: ["sh", "-lc", "echo backend-out; echo backend-err 1>&2; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let logs_default = env.run(&["logs"]);
        assert_success(&logs_default);
        assert!(stdout(&logs_default).contains("backend-err"));

        let logs_combined = env.run(&["logs", "backend"]);
        assert_success(&logs_combined);
        let combined_stdout = stdout(&logs_combined);
        assert!(combined_stdout.contains("backend-out"));
        assert!(combined_stdout.contains("backend-err"));

        let logs_err = env.run(&["logs", "backend:err"]);
        assert_success(&logs_err);
        assert!(stdout(&logs_err).contains("backend-err"));
    }

    #[test]
    fn logs_implicit_default_falls_back_to_first_process() {
        let env = TestEnv::new("logs-default-first-process");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: api
        cmd: ["sh", "-lc", "echo api-only; sleep 1"]
      - name: worker
        cmd: ["sh", "-lc", "echo worker-only; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let logs = env.run(&["logs", "--no-follow"]);
        assert_success(&logs);
        let out = stdout(&logs);
        assert!(out.contains("api-only"));
        assert!(!out.contains("worker-only"));
    }

    #[test]
    fn logs_lines_limits_initial_tail() {
        let env = TestEnv::new("logs-lines");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo L1; echo L2; echo L3; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let logs = env.run(&["logs", "app", "--lines", "2", "--no-follow"]);
        assert_success(&logs);
        let out = stdout(&logs);
        assert!(out.contains("L2"));
        assert!(out.contains("L3"));
        assert!(!out.contains("L1"));
    }

    #[test]
    fn logs_no_follow_returns_immediately() {
        let env = TestEnv::new("logs-no-follow");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: backend
        default_log: true
        cmd: ["sh", "-lc", "echo backend-out; sleep 2"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let started_at = Instant::now();
        let logs = env.run(&["logs", "--no-follow"]);
        assert_success(&logs);
        assert!(
            started_at.elapsed() < Duration::from_secs(1),
            "logs --no-follow should return without waiting for process exit"
        );
    }

    #[test]
    fn logs_invalid_target_fails() {
        let env = TestEnv::new("logs-invalid-target");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo app; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let unknown = env.run(&["logs", "worker", "--no-follow"]);
        assert_failure(&unknown);
        assert_stderr_contains(&unknown, "process `worker` is not running");

        let invalid_stream = env.run(&["logs", "app:foo", "--no-follow"]);
        assert_failure(&invalid_stream);
        assert_stderr_contains(&invalid_stream, "invalid logs stream `foo`");
    }

    #[test]
    fn q_detach_restores_terminal_and_keeps_workspace_running_with_null_stdin() {
        let env = TestEnv::new("q-detach-keeps-running");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: backend
        default_log: true
        cmd: ["sh", "-lc", "echo boot; sleep 60"]
"#,
            yaml_path(&demo),
        ));

        let mut session = env.spawn_with_pty(&["demo"], &[]);
        assert!(
            wait_for_current_status(&env, "running", Duration::from_secs(5)),
            "workspace should become running while log follow is active"
        );

        let backend_pid = current_process_pid(&env, "backend")
            .expect("backend pid should be recorded in current instance");
        assert!(pid_exists(backend_pid), "backend should still be running");

        let stdin_path = fs::read_link(format!("/proc/{backend_pid}/fd/0"))
            .expect("failed to inspect backend stdin fd link");
        assert_eq!(
            stdin_path,
            PathBuf::from("/dev/null"),
            "managed process stdin should be disconnected from wsx terminal"
        );

        session.write_bytes(b"q\n");
        let exit = session.wait_for_exit(Duration::from_secs(5));
        assert_eq!(
            exit.code(),
            Some(0),
            "q detach should exit wsx without stopping the workspace"
        );
        session.assert_terminal_restored();

        assert!(
            pid_exists(backend_pid),
            "backend should keep running after detach"
        );

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");
    }

    #[test]
    fn ctrl_c_during_workspace_follow_stops_workspace_before_exit() {
        let env = TestEnv::new("ctrlc-workspace-follow");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: backend
        default_log: true
        cmd: ["sh", "-lc", "echo boot; sleep 60"]
"#,
            yaml_path(&demo),
        ));

        let mut session = env.spawn_with_pty(&["demo"], &[]);
        assert!(
            wait_for_current_status(&env, "running", Duration::from_secs(5)),
            "workspace should become running before interrupt"
        );

        let backend_pid = current_process_pid(&env, "backend")
            .expect("backend pid should be recorded in current instance");
        assert!(
            pid_exists(backend_pid),
            "backend should be running before Ctrl+C"
        );

        session.send_sigint();
        let exit = session.wait_for_exit(Duration::from_secs(8));
        assert_eq!(
            exit.code(),
            Some(130),
            "Ctrl+C should exit with signal-compatible code 130"
        );
        session.assert_terminal_restored();

        assert!(
            wait_for_current_status(&env, "stopped", Duration::from_secs(5)),
            "Ctrl+C should stop current workspace before wsx exits"
        );
        assert!(
            wait_until(Duration::from_secs(5), || !pid_exists(backend_pid)),
            "backend process should be terminated by Ctrl+C-triggered down"
        );
    }

    #[test]
    fn ctrl_c_during_logs_follow_stops_workspace_before_exit() {
        let env = TestEnv::new("ctrlc-logs-follow");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: backend
        default_log: true
        cmd: ["sh", "-lc", "echo boot; sleep 60"]
"#,
            yaml_path(&demo),
        ));

        let mut switch_session = env.spawn_with_pty(&["demo"], &[]);
        assert!(
            wait_for_current_status(&env, "running", Duration::from_secs(5)),
            "workspace should be running after switch"
        );

        switch_session.write_bytes(b"q\n");
        let switch_exit = switch_session.wait_for_exit(Duration::from_secs(5));
        assert_eq!(switch_exit.code(), Some(0), "q detach should succeed");

        let backend_pid = current_process_pid(&env, "backend")
            .expect("backend pid should be recorded after detach");
        assert!(
            pid_exists(backend_pid),
            "backend should keep running for logs test"
        );

        let mut logs_session = env.spawn_with_pty(&["logs", "backend"], &[]);
        assert!(
            wait_for_current_status(&env, "running", Duration::from_secs(2)),
            "workspace should still be running when logs follow starts"
        );
        thread::sleep(Duration::from_millis(200));
        logs_session.send_sigint();
        let logs_exit = logs_session.wait_for_exit(Duration::from_secs(8));
        assert_eq!(
            logs_exit.code(),
            Some(130),
            "Ctrl+C on logs should exit with 130"
        );
        logs_session.assert_terminal_restored();

        assert!(
            wait_for_current_status(&env, "stopped", Duration::from_secs(5)),
            "Ctrl+C during logs follow should stop workspace"
        );
        assert!(
            wait_until(Duration::from_secs(5), || !pid_exists(backend_pid)),
            "backend process should be terminated after logs follow interrupt"
        );
    }

    #[test]
    fn multi_process_workspace_status_and_logs_targets_work() {
        let env = TestEnv::new("multi-process");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: api
        default_log: true
        cmd: ["sh", "-lc", "echo api-out; echo api-err 1>&2; sleep 1"]
      - name: worker
        cmd: ["sh", "-lc", "echo worker-out; echo worker-err 1>&2; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let status = env.run(&["status"]);
        assert_success(&status);
        let status_out = stdout(&status);
        assert!(status_out.contains("- api (pid "));
        assert!(status_out.contains("- worker (pid "));

        let logs_api = env.run(&["logs", "api"]);
        assert_success(&logs_api);
        let logs_api_out = stdout(&logs_api);
        assert!(logs_api_out.contains("api-out"));
        assert!(logs_api_out.contains("api-err"));

        let logs_worker_err = env.run(&["logs", "worker:err"]);
        assert_success(&logs_worker_err);
        assert!(stdout(&logs_worker_err).contains("worker-err"));

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");
    }

    #[test]
    fn keep_instances_trims_old_runs_to_limit() {
        let env = TestEnv::new("keep-trim");
        let cleanup = env.create_workspace("cleanup");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
  logs:
    keep_instances: 2
workspaces:
  cleanup:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo cleanup; sleep 1"]
"#,
            yaml_path(&cleanup),
        ));

        for _ in 0..4 {
            let run = env.run(&["cleanup"]);
            assert_success(&run);
        }

        let instance_ids = workspace_instance_ids(&env, "cleanup");
        assert_eq!(
            instance_ids.len(),
            2,
            "cleanup should retain exactly 2 instances"
        );

        let current_instance_id =
            current_instance_id(&env).expect("current instance should exist after switch");
        assert!(
            instance_ids.iter().any(|id| id == &current_instance_id),
            "latest current instance must be retained"
        );
    }

    #[test]
    fn keep_instances_zero_disables_cleanup() {
        let env = TestEnv::new("keep-zero");
        let noclean = env.create_workspace("noclean");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
  logs:
    keep_instances: 0
workspaces:
  noclean:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo noclean; sleep 1"]
"#,
            yaml_path(&noclean),
        ));

        for expected_count in 1..=4 {
            let run = env.run(&["noclean"]);
            assert_success(&run);

            let instance_ids = workspace_instance_ids(&env, "noclean");
            assert_eq!(
                instance_ids.len(),
                expected_count,
                "keep_instances=0 should not delete old instances"
            );
        }
    }

    #[test]
    fn keep_instances_is_scoped_per_workspace() {
        let env = TestEnv::new("keep-scope");
        let alpha = env.create_workspace("alpha");
        let beta = env.create_workspace("beta");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  alpha:
    path: {}
    logs:
      keep_instances: 1
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo alpha; sleep 1"]
  beta:
    path: {}
    logs:
      keep_instances: 1
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo beta; sleep 1"]
"#,
            yaml_path(&alpha),
            yaml_path(&beta),
        ));

        for _ in 0..3 {
            let run_alpha = env.run(&["alpha"]);
            assert_success(&run_alpha);

            let run_beta = env.run(&["beta"]);
            assert_success(&run_beta);
        }

        let alpha_instances = workspace_instance_ids(&env, "alpha");
        let beta_instances = workspace_instance_ids(&env, "beta");
        assert_eq!(
            alpha_instances.len(),
            1,
            "alpha should retain only one instance"
        );
        assert_eq!(
            beta_instances.len(),
            1,
            "beta should retain only one instance"
        );

        let current_instance_id =
            current_instance_id(&env).expect("current instance should exist after switch");
        assert!(
            beta_instances.iter().any(|id| id == &current_instance_id),
            "current instance should be beta's latest instance"
        );
    }

    #[test]
    fn envrc_uses_non_login_shell() {
        let env = TestEnv::new("envrc-non-login-shell");
        let demo = env.create_workspace("demo");

        let fake_bin = env.home_dir.join("fake-bin");
        fs::create_dir_all(&fake_bin).expect("failed to create fake bin");

        let sh_shim = fake_bin.join("sh");
        fs::write(
            &sh_shim,
            r#"#!/bin/sh
if [ -n "${WSX_SH_ARG_FILE:-}" ]; then
  printf '%s' "$1" > "$WSX_SH_ARG_FILE"
fi
exec /bin/sh "$@"
"#,
        )
        .expect("failed to write sh shim");
        fs::set_permissions(&sh_shim, fs::Permissions::from_mode(0o755))
            .expect("failed to chmod sh shim");

        fs::write(demo.join(".envrc"), "export WSX_ENVRC_MARKER=loaded\n")
            .expect("failed to write .envrc");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: true
workspaces:
  demo:
    path: {}
    processes:
      - name: envdump
        cmd: ["sh", "-c", "echo \"$WSX_ENVRC_MARKER\""]
"#,
            yaml_path(&demo),
        ));

        let sh_arg_file = env.home_dir.join("sh-arg.txt");
        let host_path = std::env::var("PATH").expect("PATH should be set in test env");
        let merged_path = format!("{}:{host_path}", fake_bin.display());
        let sh_arg_path = sh_arg_file.to_string_lossy().to_string();

        let switch = env.run_with_env(
            &["demo"],
            &[
                ("PATH", merged_path.as_str()),
                ("WSX_SH_ARG_FILE", sh_arg_path.as_str()),
            ],
        );
        assert_success(&switch);
        let switch_stdout = stdout(&switch);
        assert!(
            switch_stdout.lines().any(|line| line.trim() == "loaded"),
            "envrc output should be applied to child process environment"
        );

        let recorded_flag =
            fs::read_to_string(&sh_arg_file).expect("sh shim should record the first arg");
        assert_eq!(
            recorded_flag, "-c",
            ".envrc shell must run as non-login shell"
        );
    }

    #[test]
    fn dotenv_overrides_os_env() {
        let env = TestEnv::new("dotenv-overrides-os");
        let demo = env.create_workspace("demo");

        fs::write(demo.join(".env"), "WSX_PRIORITY=from-dotenv\n").expect("failed to write .env");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: envdump
        cmd: ["sh", "-c", "echo \"$WSX_PRIORITY\""]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run_with_env(&["demo"], &[("WSX_PRIORITY", "from-os")]);
        assert_success(&switch);
        assert_stdout_contains_all(&switch, &["from-dotenv"]);
    }

    #[test]
    fn envrc_overrides_dotenv() {
        let env = TestEnv::new("envrc-overrides-dotenv");
        let demo = env.create_workspace("demo");

        fs::write(demo.join(".env"), "WSX_PRIORITY=from-dotenv\n").expect("failed to write .env");
        fs::write(demo.join(".envrc"), "export WSX_PRIORITY=from-envrc\n")
            .expect("failed to write .envrc");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: true
workspaces:
  demo:
    path: {}
    processes:
      - name: envdump
        cmd: ["sh", "-c", "echo \"$WSX_PRIORITY\""]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);
        assert_stdout_contains_all(&switch, &["from-envrc"]);
    }

    #[test]
    fn envrc_missing_is_noop() {
        let env = TestEnv::new("envrc-missing");
        let demo = env.create_workspace("demo");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: true
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-c", "echo no-envrc-ok"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);
        assert_stdout_contains_all(&switch, &["no-envrc-ok"]);
    }

    #[test]
    fn envrc_failure_aborts_start() {
        let env = TestEnv::new("envrc-failure");
        let demo = env.create_workspace("demo");

        fs::write(demo.join(".envrc"), "exit 7\n").expect("failed to write .envrc");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: true
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-c", "echo should-not-run"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_failure(&switch);
        assert_stderr_contains(&switch, ".envrc execution failed");
        assert!(
            current_instance_id(&env).is_none(),
            "current should not be saved when envrc evaluation fails"
        );
    }

    #[test]
    fn down_kills_background_child_processes() {
        let env = TestEnv::new("down-kills-child-processes");
        let demo = env.create_workspace("demo");
        let child_pid_path = demo.join("child.pid");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: launcher
        cmd: ["sh", "-c", "sleep 60 & echo $! > child.pid"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        assert!(
            wait_until(Duration::from_secs(2), || child_pid_path.exists()),
            "child pid file was not created"
        );
        let child_pid: u32 = fs::read_to_string(&child_pid_path)
            .expect("failed to read child pid file")
            .trim()
            .parse()
            .expect("child pid must be numeric");
        assert!(
            pid_exists(child_pid),
            "background child process should be running before down"
        );

        let down = env.run(&["down"]);
        assert_success(&down);
        assert!(
            wait_until(Duration::from_secs(3), || !pid_exists(child_pid)),
            "background child process should be terminated by down"
        );
    }

    #[test]
    fn switch_stops_previous_workspace_processes() {
        let env = TestEnv::new("switch-stops-previous");
        let alpha = env.create_workspace("alpha");
        let beta = env.create_workspace("beta");
        let alpha_child_pid_path = alpha.join("child.pid");

        env.write_config(&format!(
            r#"defaults:
  stop:
    grace_seconds: 1
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  alpha:
    path: {}
    processes:
      - name: short
        default_log: true
        cmd: ["sh", "-lc", "echo alpha-short; sleep 1"]
      - name: launcher
        cmd: ["sh", "-c", "sleep 60 & echo $! > child.pid; sleep 60"]
  beta:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo beta; sleep 1"]
"#,
            yaml_path(&alpha),
            yaml_path(&beta),
        ));

        let switch_alpha = env.run(&["alpha"]);
        assert_success(&switch_alpha);
        assert!(
            wait_until(Duration::from_secs(2), || alpha_child_pid_path.exists()),
            "alpha child pid file should be created before switching"
        );

        let child_pid: u32 = fs::read_to_string(&alpha_child_pid_path)
            .expect("failed to read alpha child pid")
            .trim()
            .parse()
            .expect("alpha child pid must be numeric");
        assert!(
            pid_exists(child_pid),
            "alpha child process should be running before switching to beta"
        );

        let switch_beta = env.run(&["beta"]);
        assert_success(&switch_beta);
        assert!(
            wait_until(Duration::from_secs(3), || !pid_exists(child_pid)),
            "switch should stop previous workspace background child process"
        );
    }

    #[test]
    fn exec_runs_command_in_current_workspace() {
        let env = TestEnv::new("exec");
        let demo = env.create_workspace("demo");
        let marker = demo.join("exec-result.txt");

        fs::write(demo.join(".env"), "WSX_EXEC_MARK=from-dotenv\n").expect("failed to write .env");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo boot; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let exec = env.run(&[
            "exec",
            "sh",
            "-c",
            "printf '%s' \"$WSX_EXEC_MARK\" > exec-result.txt",
        ]);
        assert_success(&exec);

        let marker_content = fs::read_to_string(marker).expect("exec marker should be created");
        assert_eq!(marker_content, "from-dotenv");
    }

    #[test]
    fn exec_runs_in_workspace_cwd() {
        let env = TestEnv::new("exec-cwd");
        let demo = env.create_workspace("demo");
        let cwd_marker = demo.join("cwd.txt");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo boot; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let exec = env.run(&["exec", "sh", "-c", "pwd > cwd.txt"]);
        assert_success(&exec);

        let cwd = fs::read_to_string(cwd_marker).expect("cwd marker should be created");
        assert_eq!(cwd.trim(), demo.to_string_lossy());
    }

    #[test]
    fn exec_works_when_current_is_stopped() {
        let env = TestEnv::new("exec-while-stopped");
        let demo = env.create_workspace("demo");
        let marker = demo.join("exec-stopped.txt");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  demo:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo boot; sleep 1"]
"#,
            yaml_path(&demo),
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let status = env.run(&["status"]);
        assert_success(&status);
        assert_stdout_contains_all(&status, &["State: stopped"]);

        let exec = env.run(&["exec", "sh", "-c", "echo ok > exec-stopped.txt"]);
        assert_success(&exec);

        let marker_content =
            fs::read_to_string(marker).expect("exec marker for stopped current should exist");
        assert_eq!(marker_content.trim(), "ok");
    }

    #[test]
    fn invalid_workspace_returns_error() {
        let env = TestEnv::new("invalid-workspace");
        let known = env.create_workspace("known");

        env.write_config(&format!(
            r#"defaults:
  env:
    dotenv: [.env]
    envrc: false
workspaces:
  known:
    path: {}
    processes:
      - name: app
        cmd: ["sh", "-lc", "echo known; sleep 1"]
"#,
            yaml_path(&known),
        ));

        let result = env.run(&["unknown"]);
        assert_failure(&result);
        assert!(stderr(&result).contains("workspace `unknown` is not defined"));
    }
}
