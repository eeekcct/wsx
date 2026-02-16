#[cfg(target_os = "linux")]
mod linux_e2e {
    use serde::Deserialize;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
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
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_wsx"));
            cmd.args(args)
                .env("HOME", &self.home_dir)
                .env_remove("WSX_HOME");
            for (key, value) in extra_env {
                cmd.env(key, value);
            }
            cmd.output().expect("failed to execute wsx")
        }

        fn wsx_home(&self) -> PathBuf {
            self.home_dir.join(".config").join("wsx")
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

    #[derive(Debug, Deserialize)]
    struct PidsMeta {
        workspace: String,
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
        let down_stdout = stdout(&down);
        assert!(down_stdout.contains("stopped workspace `deva`"));

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
        let down_stdout = stdout(&down);
        assert!(down_stdout.contains("stopped workspace `demo`"));

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
        assert!(stdout(&down).contains("stopped workspace `demo`"));
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
