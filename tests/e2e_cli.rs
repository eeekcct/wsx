#[cfg(target_os = "linux")]
mod linux_e2e {
    use serde::Deserialize;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::time::{SystemTime, UNIX_EPOCH};

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
                .env_remove("WSX_HOME");
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
        assert!(stdout(&status_after_down).contains("Current: none"));
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
