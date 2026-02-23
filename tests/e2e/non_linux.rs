#[cfg(any(target_os = "windows", target_os = "macos"))]
mod non_linux_e2e {
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
                .env("USERPROFILE", &self.home_dir)
                .env("HOMEDRIVE", "")
                .env("HOMEPATH", "")
                .env_remove("WSX_HOME");
            cmd.output().expect("failed to execute wsx")
        }

        fn wsx_home(&self) -> PathBuf {
            self.home_dir.join(".config").join("wsx")
        }
    }

    #[derive(Debug, Deserialize)]
    struct CurrentMeta {
        instance_id: String,
        status: Option<String>,
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
        assert_stdout_contains_all(&status, &["Current workspace: demo", "- app (pid "]);

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
        assert_ne!(meta_after_up.instance_id, first_instance);
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
