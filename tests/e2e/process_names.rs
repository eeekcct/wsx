#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use uuid::Uuid;

struct TempRoot(PathBuf);
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn colliding_generated_names_keep_separate_log_targets() {
    let root = TempRoot(std::env::temp_dir().join(format!("wsx-process-names-{}", Uuid::new_v4())));
    let home = root.0.join("home");
    let workspace = root.0.join("workspace");
    let config = home.join(".config/wsx");
    fs::create_dir_all(&config).unwrap();
    fs::create_dir_all(&workspace).unwrap();
    fs::write(
        config.join("config.yaml"),
        json!({
            "workspaces": {"demo": {"path": workspace, "processes": [
                {"name":"app", "cmd":["/bin/sh","-c","echo A; sleep 0.1"]},
                {"name":"app", "cmd":["/bin/sh","-c","echo B"]},
                {"name":"app-2", "cmd":["/bin/sh","-c","echo C"]}
            ]}}
        })
        .to_string(),
    )
    .unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_wsx"))
            .args(args)
            .current_dir(&root.0)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("WSX_LOG", "error")
            .stdin(Stdio::null())
            .output()
            .expect("run wsx");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8 fixture output")
    };
    run(&["demo"]);
    let current: Value =
        serde_json::from_str(&fs::read_to_string(config.join("current.json")).unwrap()).unwrap();
    let pids: Value = serde_json::from_str(
        &fs::read_to_string(
            config
                .join("instances")
                .join(current["instance_id"].as_str().unwrap())
                .join("pids.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let names: Vec<_> = pids["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["app", "app-2", "app-2-2"]);
    assert_eq!(run(&["logs", "app:out", "--no-follow"]), "A\n");
    assert_eq!(run(&["logs", "app-2:out", "--no-follow"]), "B\n");
    assert_eq!(run(&["logs", "app-2-2:out", "--no-follow"]), "C\n");
    run(&["down"]);
}
