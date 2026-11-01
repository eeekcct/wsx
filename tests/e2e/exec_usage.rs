#![cfg(target_os = "linux")]

use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("wsx-exec-usage-{}", Uuid::new_v4()));
        let home = root.join("home");
        let workspace = root.join("workspace");
        fs::create_dir_all(home.join(".config/wsx")).expect("create isolated home");
        fs::create_dir_all(&workspace).expect("create isolated workspace");
        fs::write(
            home.join(".config/wsx/config.yaml"),
            json!({
                "defaults": {"env": {"dotenv": [], "envrc": false}},
                "workspaces": {"demo": {"path": workspace, "processes": [{"cmd": ["/bin/true"]}]}}
            })
            .to_string(),
        )
        .expect("write config");
        Self { root, home }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wsx"))
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("WSX_LOG", "error")
            .stdin(Stdio::null())
            .output()
            .expect("run wsx")
    }

    fn current_path(&self) -> PathBuf {
        self.home.join(".config/wsx/current.json")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn bare_exec_is_a_usage_error_before_config_or_workspace_loading() {
    let fixture = Fixture::new();
    assert_success(&fixture.run(&["select", "demo"]));
    let before = fs::read(fixture.current_path()).expect("selected state");
    for args in [&["exec"][..], &["exec", "--"][..]] {
        let output = fixture.run(args);
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("required arguments"));
        assert!(!stderr.contains("panicked"));
    }
    assert_eq!(fs::read(fixture.current_path()).unwrap(), before);
    fs::remove_file(fixture.home.join(".config/wsx/config.yaml")).expect("remove own config");
    let output = fixture.run(&["exec"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("config file not found"));
}
