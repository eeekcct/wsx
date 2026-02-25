#[cfg(target_os = "windows")]
mod windows_e2e {
    use serde::Deserialize;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Output};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use sysinfo::System;

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
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_wsx"));
            cmd.args(args)
                .env("HOME", &self.home_dir)
                .env("USERPROFILE", &self.home_dir)
                .env("HOMEDRIVE", "")
                .env("HOMEPATH", "")
                .env_remove("WSX_HOME");
            cmd.output().expect("failed to execute wsx")
        }

        fn run_status(&self, args: &[&str]) -> ExitStatus {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_wsx"));
            cmd.args(args)
                .env("HOME", &self.home_dir)
                .env("USERPROFILE", &self.home_dir)
                .env("HOMEDRIVE", "")
                .env("HOMEPATH", "")
                .env_remove("WSX_HOME");
            cmd.status().expect("failed to execute wsx")
        }

        fn wsx_home(&self) -> PathBuf {
            self.home_dir.join(".config").join("wsx")
        }
    }

    #[derive(Debug, Deserialize)]
    struct CurrentMeta {
        instance_id: Option<String>,
        status: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct PidsMeta {
        entries: Vec<PidEntryMeta>,
    }

    #[derive(Debug, Deserialize)]
    struct PidEntryMeta {
        pid: u32,
    }

    fn yaml_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    fn yaml_path(path: &Path) -> String {
        yaml_quote(&path.display().to_string())
    }

    fn yaml_cmd(parts: &[&str]) -> String {
        let joined = parts
            .iter()
            .map(|part| yaml_quote(part))
            .collect::<Vec<_>>()
            .join(", ");
        format!("[{joined}]")
    }

    fn python_cmd(script: &str) -> String {
        yaml_cmd(&["python", "-c", script])
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

    fn assert_status_success(status: ExitStatus) {
        assert!(
            status.success(),
            "expected success status, exit={:?}",
            status.code()
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

    fn current_instance_id(env: &TestEnv) -> Option<String> {
        let current_path = env.wsx_home().join("current.json");
        if !current_path.exists() {
            return None;
        }
        let raw = fs::read_to_string(current_path).expect("failed to read current.json");
        let current: CurrentMeta = serde_json::from_str(&raw).expect("invalid current.json");
        current.instance_id
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

    fn current_process_pids(env: &TestEnv) -> Option<Vec<u32>> {
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
        Some(meta.entries.iter().map(|entry| entry.pid).collect())
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
        let script = format!(
            "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($null -eq $p) {{ exit 1 }} else {{ exit 0 }}"
        );
        match Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
        {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }

    fn snapshot_process_tree(root_pids: &[u32]) -> Vec<u32> {
        let mut system = System::new_all();
        system.refresh_all();

        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for (pid, process) in system.processes() {
            let Some(parent) = process.parent() else {
                continue;
            };
            children
                .entry(parent.as_u32())
                .or_default()
                .push(pid.as_u32());
        }

        let mut tracked = HashSet::new();
        let mut stack = root_pids.to_vec();
        while let Some(pid) = stack.pop() {
            if !tracked.insert(pid) {
                continue;
            }
            if let Some(child_pids) = children.get(&pid) {
                stack.extend(child_pids.iter().copied());
            }
        }

        let mut out = tracked.into_iter().collect::<Vec<_>>();
        out.sort_unstable();
        out
    }

    fn assert_no_running_pids(pids: &[u32], timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let alive = pids
                .iter()
                .copied()
                .filter(|pid| pid_exists(*pid))
                .collect::<Vec<_>>();
            if alive.is_empty() {
                return;
            }

            if Instant::now() >= deadline {
                panic!(
                    "processes remained after {:?}: {}",
                    timeout,
                    alive
                        .into_iter()
                        .map(|pid| pid.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn list_sorts_and_marks_current() {
        let env = TestEnv::new("nonlinux-list");
        let zeta = env.create_workspace("zeta");
        let alpha = env.create_workspace("alpha");
        let alpha_cmd = python_cmd(r#"import time; print("alpha", flush=True); time.sleep(1)"#);
        let zeta_cmd = python_cmd(r#"import time; print("zeta", flush=True); time.sleep(1)"#);

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
        cmd: {}
  alpha:
    path: {}
    processes:
      - name: app
        cmd: {}
"#,
            yaml_path(&zeta),
            zeta_cmd,
            yaml_path(&alpha),
            alpha_cmd,
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
        assert_stdout_contains_all(&list_after, &["* alpha", "  zeta"]);
    }

    #[test]
    fn down_noops_when_no_current() {
        let env = TestEnv::new("nonlinux-down-no-current");
        let down = env.run(&["down"]);
        assert_success(&down);
        assert_stdout_contains_all(&down, &["no current workspace"]);
    }

    #[test]
    fn up_and_logs_without_current_fail() {
        let env = TestEnv::new("nonlinux-no-current-fails");

        let up = env.run(&["up"]);
        assert_failure(&up);
        assert_stderr_contains(&up, "no current workspace");

        let logs = env.run(&["logs", "--no-follow"]);
        assert_failure(&logs);
        assert_stderr_contains(&logs, "no current workspace");
    }

    #[test]
    fn workspace_and_subcommand_together_fails() {
        let env = TestEnv::new("nonlinux-workspace-and-subcommand");
        let result = env.run(&["list", "demo"]);
        assert_failure(&result);
        assert_stderr_contains(&result, "unexpected argument");
    }

    #[test]
    fn select_sets_stopped_without_starting_processes() {
        let env = TestEnv::new("nonlinux-select-stopped-no-start");
        let demo = env.create_workspace("demo");
        let marker = demo.join("started.txt");
        let app_cmd = python_cmd(
            r#"import pathlib,time; pathlib.Path("started.txt").write_text("started\n"); time.sleep(60)"#,
        );

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
        ));

        let select = env.run(&["select", "demo"]);
        assert_success(&select);
        assert_stdout_contains_all(&select, &["selected workspace `demo`"]);
        assert!(
            !marker.exists(),
            "select should not start workspace processes"
        );

        let meta = current_meta(&env).expect("current should exist after select");
        assert_eq!(meta.status.as_deref(), Some("stopped"));
        assert_eq!(meta.instance_id, None);

        let status = env.run(&["status"]);
        assert_success(&status);
        assert_stdout_contains_all(
            &status,
            &[
                "Current workspace: demo",
                "State: stopped",
                "Instance ID: (none)",
                "Processes: unavailable (no running instance)",
            ],
        );
    }

    #[test]
    fn down_after_select_succeeds() {
        let env = TestEnv::new("nonlinux-down-after-select");
        let demo = env.create_workspace("demo");
        let app_cmd = python_cmd(r#"import time; print("demo", flush=True); time.sleep(60)"#);

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
        ));

        let select = env.run(&["select", "demo"]);
        assert_success(&select);

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");
    }

    #[test]
    fn up_after_select_starts_workspace_and_sets_instance_id() {
        let env = TestEnv::new("nonlinux-up-after-select");
        let demo = env.create_workspace("demo");
        let app_cmd = python_cmd(r#"import time; print("demo", flush=True); time.sleep(1)"#);

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
        ));

        let select = env.run(&["select", "demo"]);
        assert_success(&select);

        let up = env.run(&["up"]);
        assert_success(&up);
        assert_stdout_contains_all(&up, &["started workspace `demo`"]);

        let meta = current_meta(&env).expect("current should exist after up");
        assert!(
            meta.instance_id.is_some(),
            "up should set instance_id after select"
        );
    }

    #[test]
    fn config_missing_file_returns_error() {
        let env = TestEnv::new("nonlinux-config-missing");
        let list = env.run(&["list"]);
        assert_failure(&list);
        assert_stderr_contains(&list, "config file not found");
    }

    #[test]
    fn config_with_empty_workspaces_returns_error() {
        let env = TestEnv::new("nonlinux-config-empty-workspaces");
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
        let env = TestEnv::new("nonlinux-workspace-no-processes");
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
    fn status_reconciles_when_stale_running() {
        let env = TestEnv::new("nonlinux-status-reconcile");
        let demo = env.create_workspace("demo");
        let app_cmd = python_cmd(r#"import time; print("demo-run", flush=True); time.sleep(1)"#);

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let before_status = current_meta(&env).expect("current should exist after switch");
        assert_eq!(before_status.status.as_deref(), Some("running"));

        let status = env.run(&["status"]);
        assert_success(&status);
        assert!(stdout(&status).contains("State: stopped"));

        let after_status = current_meta(&env).expect("current should exist after status");
        assert_eq!(after_status.status.as_deref(), Some("stopped"));
    }

    #[test]
    fn up_restarts_when_stale_running() {
        let env = TestEnv::new("nonlinux-up-restarts-stale-running");
        let demo = env.create_workspace("demo");
        let app_cmd = python_cmd(r#"import time; print("demo-run", flush=True); time.sleep(1)"#);

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
        ));

        let first_switch = env.run(&["demo"]);
        assert_success(&first_switch);
        let first_instance =
            current_instance_id(&env).expect("current instance should exist after first switch");

        let up = env.run(&["up"]);
        assert_success(&up);
        assert_stdout_contains_all(&up, &["started workspace `demo`"]);

        let meta_after_up = current_meta(&env).expect("current should exist after up");
        assert_ne!(
            meta_after_up.instance_id.as_deref(),
            Some(first_instance.as_str())
        );
    }

    #[test]
    fn logs_default_and_explicit_stream_work() {
        let env = TestEnv::new("nonlinux-logs");
        let demo = env.create_workspace("demo");
        let backend_cmd = python_cmd(
            r#"import time,sys; print("backend-out", flush=True); print("backend-err", file=sys.stderr, flush=True); time.sleep(1)"#,
        );

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
        cmd: {}
"#,
            yaml_path(&demo),
            backend_cmd,
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let logs_default = env.run(&["logs", "--no-follow"]);
        assert_success(&logs_default);
        assert!(stdout(&logs_default).contains("backend-err"));

        let logs_combined = env.run(&["logs", "backend", "--no-follow"]);
        assert_success(&logs_combined);
        let combined_stdout = stdout(&logs_combined);
        assert!(combined_stdout.contains("backend-out"));
        assert!(combined_stdout.contains("backend-err"));

        let logs_err = env.run(&["logs", "backend:err", "--no-follow"]);
        assert_success(&logs_err);
        assert!(stdout(&logs_err).contains("backend-err"));
    }

    #[test]
    fn logs_invalid_target_fails() {
        let env = TestEnv::new("nonlinux-logs-invalid-target");
        let demo = env.create_workspace("demo");
        let app_cmd = python_cmd(r#"import time; print("app", flush=True); time.sleep(1)"#);

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
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
    fn switch_status_and_down_happy_path() {
        let env = TestEnv::new("nonlinux-lifecycle");
        let demo = env.create_workspace("demo");
        let app_cmd = python_cmd(
            r#"import time,sys; print("app-out", flush=True); print("app-err", file=sys.stderr, flush=True); time.sleep(1)"#,
        );

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);
        assert_stdout_contains_all(&switch, &["switched to workspace `demo`"]);

        let status = env.run(&["status"]);
        assert_success(&status);
        let status_out = stdout(&status);
        assert!(
            status_out.contains("Current workspace: demo"),
            "status should show current workspace\nstdout:\n{}\nstderr:\n{}",
            status_out,
            stderr(&status)
        );
        assert!(
            status_out.contains("- app (pid ")
                || status_out.contains("Processes: unavailable (no running instance)"),
            "status should show either running pid info or reconciled no-running state\nstdout:\n{}\nstderr:\n{}",
            status_out,
            stderr(&status)
        );

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");
    }

    #[test]
    fn down_and_up_restart_current_workspace() {
        let env = TestEnv::new("nonlinux-down-up");
        let demo = env.create_workspace("demo");
        let app_cmd = python_cmd(r#"import time; print("demo-run", flush=True); time.sleep(1)"#);

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
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
        assert_stdout_contains_all(&up, &["started workspace `demo`"]);
        let meta_after_up = current_meta(&env).expect("current should exist after up");
        assert_eq!(meta_after_up.status.as_deref(), Some("running"));
        assert_ne!(
            meta_after_up.instance_id.as_deref(),
            Some(first_instance.as_str())
        );
    }

    #[test]
    fn down_keeps_instance_and_logs_remain_available() {
        let env = TestEnv::new("nonlinux-down-keeps-instance");
        let demo = env.create_workspace("demo");
        let app_cmd = python_cmd(r#"import time; print("demo-run", flush=True); time.sleep(1)"#);

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);
        let instance_id =
            current_instance_id(&env).expect("current instance should exist after switch");

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");

        let meta = current_meta(&env).expect("current should exist after down");
        assert_eq!(meta.status.as_deref(), Some("stopped"));
        assert_eq!(meta.instance_id.as_deref(), Some(instance_id.as_str()));

        let logs = env.run(&["logs", "--no-follow"]);
        assert_success(&logs);
        assert_stdout_contains_all(&logs, &["demo-run"]);
    }

    #[test]
    fn down_recovers_when_running_instance_metadata_is_missing() {
        let env = TestEnv::new("nonlinux-down-missing-pids");
        let demo = env.create_workspace("demo");
        let short_cmd = python_cmd(r#"import time; print("short", flush=True); time.sleep(1)"#);
        let long_cmd = python_cmd(r#"import time; print("long", flush=True); time.sleep(30)"#);

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
        cmd: {}
      - name: long
        cmd: {}
"#,
            yaml_path(&demo),
            short_cmd,
            long_cmd,
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let instance_id =
            current_instance_id(&env).expect("current instance should exist after switch");
        let pids_path = env
            .wsx_home()
            .join("instances")
            .join(instance_id)
            .join("pids.json");
        fs::remove_file(&pids_path).expect("failed to remove pids.json");

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_stdout_contains_all(&down, &["marked as stopped"]);

        let meta = current_meta(&env).expect("current should exist after recovery");
        assert_eq!(meta.status.as_deref(), Some("stopped"));
        assert_eq!(meta.instance_id, None);
    }

    #[test]
    fn switch_then_up_reports_already_running() {
        let env = TestEnv::new("nonlinux-up-already-running");
        let demo = env.create_workspace("demo");
        let short_cmd = python_cmd(r#"import time; print("short", flush=True); time.sleep(1)"#);
        let long_cmd = python_cmd(r#"import time; time.sleep(10)"#);

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
        cmd: {}
      - name: long
        cmd: {}
"#,
            yaml_path(&demo),
            short_cmd,
            long_cmd,
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let up = env.run(&["up"]);
        assert_success(&up);
        let up_stdout = stdout(&up);
        assert!(
            up_stdout.contains("workspace `demo` is already running")
                || up_stdout.contains("started workspace `demo`"),
            "up output should indicate either already-running or restart behavior\nstdout:\n{}\nstderr:\n{}",
            up_stdout,
            stderr(&up)
        );

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");
    }

    #[test]
    fn down_kills_background_child_processes_without_residual_pids() {
        let env = TestEnv::new("nonlinux-down-kills-child-processes");
        let demo = env.create_workspace("demo");
        let short_cmd = python_cmd(r#"import time; print("short", flush=True); time.sleep(1)"#);
        let launcher_cmd = python_cmd(
            r#"import pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]); pathlib.Path("child.pid").write_text(str(child.pid)); time.sleep(60)"#,
        );
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
    logs:
      default: short
    processes:
      - name: short
        default_log: true
        cmd: {}
      - name: launcher
        cmd: {}
"#,
            yaml_path(&demo),
            short_cmd,
            launcher_cmd,
        ));

        assert_status_success(env.run_status(&["demo"]));

        assert!(
            wait_until(Duration::from_secs(2), || child_pid_path.exists()),
            "child pid file was not created"
        );
        let child_pid: u32 = fs::read_to_string(&child_pid_path)
            .expect("failed to read child pid")
            .trim()
            .parse()
            .expect("child pid should be numeric");
        assert!(
            wait_until(Duration::from_secs(2), || pid_exists(child_pid)),
            "background child process should be running before down"
        );

        let managed_root_pids =
            current_process_pids(&env).expect("managed pids should exist before down");
        let mut tracked_tree = snapshot_process_tree(&managed_root_pids);
        tracked_tree.push(child_pid);
        tracked_tree.sort_unstable();
        tracked_tree.dedup();

        let down = env.run(&["down"]);
        assert_success(&down);
        assert_down_succeeded_message(&down, "demo");
        assert!(
            wait_until(Duration::from_secs(3), || !pid_exists(child_pid)),
            "background child process should be terminated by down"
        );
        assert_no_running_pids(&tracked_tree, Duration::from_secs(3));
    }

    #[test]
    fn switch_stops_previous_workspace_without_residual_pids() {
        let env = TestEnv::new("nonlinux-switch-stops-previous");
        let alpha = env.create_workspace("alpha");
        let beta = env.create_workspace("beta");
        let alpha_short_cmd =
            python_cmd(r#"import time; print("alpha-short", flush=True); time.sleep(1)"#);
        let alpha_launcher_cmd = python_cmd(
            r#"import pathlib,subprocess,sys,time; child=subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]); pathlib.Path("child.pid").write_text(str(child.pid)); time.sleep(60)"#,
        );
        let beta_cmd = python_cmd(r#"import time; print("beta", flush=True); time.sleep(1)"#);
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
    logs:
      default: short
    processes:
      - name: short
        default_log: true
        cmd: {}
      - name: launcher
        cmd: {}
  beta:
    path: {}
    processes:
      - name: app
        cmd: {}
"#,
            yaml_path(&alpha),
            alpha_short_cmd,
            alpha_launcher_cmd,
            yaml_path(&beta),
            beta_cmd,
        ));

        assert_status_success(env.run_status(&["alpha"]));
        assert!(
            wait_until(Duration::from_secs(2), || alpha_child_pid_path.exists()),
            "alpha child pid file should exist before switching"
        );

        let child_pid: u32 = fs::read_to_string(&alpha_child_pid_path)
            .expect("failed to read alpha child pid")
            .trim()
            .parse()
            .expect("alpha child pid should be numeric");
        assert!(
            wait_until(Duration::from_secs(2), || pid_exists(child_pid)),
            "alpha child process should be running before switch"
        );
        let managed_root_pids =
            current_process_pids(&env).expect("alpha managed pids should exist");
        let mut tracked_tree = snapshot_process_tree(&managed_root_pids);
        tracked_tree.push(child_pid);
        tracked_tree.sort_unstable();
        tracked_tree.dedup();

        assert_status_success(env.run_status(&["beta"]));
        assert!(
            wait_until(Duration::from_secs(3), || !pid_exists(child_pid)),
            "switch should terminate previous workspace background child process"
        );
        assert_no_running_pids(&tracked_tree, Duration::from_secs(3));
    }

    #[test]
    fn exec_runs_command_in_current_workspace() {
        let env = TestEnv::new("nonlinux-exec");
        let demo = env.create_workspace("demo");
        let app_cmd = python_cmd(r#"import time; print("boot", flush=True); time.sleep(1)"#);

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
        cmd: {}
"#,
            yaml_path(&demo),
            app_cmd,
        ));

        let switch = env.run(&["demo"]);
        assert_success(&switch);

        let exec_marker = env.run(&[
            "exec",
            "python",
            "-c",
            "import pathlib; pathlib.Path('exec-result.txt').write_text('ok\\n')",
        ]);
        assert_success(&exec_marker);
        let marker_path = demo.join("exec-result.txt");
        let marker_content = fs::read_to_string(marker_path).expect("exec marker should exist");
        assert_eq!(marker_content.trim(), "ok");

        let exec_cwd = env.run(&[
            "exec",
            "python",
            "-c",
            "import os,pathlib; pathlib.Path('cwd.txt').write_text(os.getcwd())",
        ]);
        assert_success(&exec_cwd);
        let cwd = fs::read_to_string(demo.join("cwd.txt")).expect("cwd marker should be created");
        let actual_cwd = fs::canonicalize(PathBuf::from(cwd.trim()))
            .expect("cwd from exec should point to an existing directory");
        let expected_cwd = fs::canonicalize(&demo)
            .expect("workspace path should resolve to an existing directory");
        assert_eq!(actual_cwd, expected_cwd);
    }

    #[test]
    fn invalid_workspace_returns_error() {
        let env = TestEnv::new("nonlinux-invalid-workspace");
        let known = env.create_workspace("known");
        let app_cmd = python_cmd(r#"import time; print("known", flush=True); time.sleep(1)"#);

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
        cmd: {}
"#,
            yaml_path(&known),
            app_cmd,
        ));

        let result = env.run(&["unknown"]);
        assert_failure(&result);
        assert_stderr_contains(&result, "workspace `unknown` is not defined");
    }
}
