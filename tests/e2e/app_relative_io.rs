#![cfg(target_os = "linux")]

use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
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
fn apps_read_and_write_relative_files_in_workspace_not_invocation_directory() {
    let root = TempRoot(std::env::temp_dir().join(format!("wsx-app-relative-{}", Uuid::new_v4())));
    let home = root.0.join("home");
    let config_dir = home.join(".config/wsx");
    let caller = root.0.join("呼び出し元 A with spaces");
    let workspace = root.0.join("アプリ B with spaces");
    fs::create_dir_all(&config_dir).expect("create isolated config");
    for (dir, identity) in [(&caller, "A-decoy"), (&workspace, "B-workspace")] {
        fs::create_dir_all(dir.join("assets")).expect("create assets");
        fs::create_dir_all(dir.join("output")).expect("create output");
        fs::write(
            dir.join("config.json"),
            format!("{{\"source\":\"{identity}\"}}\n"),
        )
        .expect("write relative config");
        fs::write(dir.join("assets/data.txt"), format!("{identity}-asset\n"))
            .expect("write relative asset");
        fs::write(dir.join("assets/child.txt"), format!("{identity}-child\n"))
            .expect("write nested-child asset");
        fs::write(dir.join(".env"), format!("WSX_APP_SOURCE={identity}-env\n"))
            .expect("write dotenv");
        for tag in ["start", "exec tag 日本語", "start-shell", "exec-shell"] {
            fs::write(dir.join("output").join(format!("{tag}.txt")), "untouched\n")
                .expect("write output decoy");
        }
    }
    let script = workspace.join("app script.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
set -eu
tag="$1"
cat ./config.json ./assets/data.txt > "./output/$tag.txt"
printf '%s\n' "$WSX_APP_SOURCE" >> "./output/$tag.txt"
pwd > "./output/cwd-$tag.txt"
/bin/sh -c 'cat ./assets/child.txt > "./output/child-$1.txt"; pwd > "./output/child-cwd-$1.txt"' child "$tag"
"#,
    )
    .expect("write relative app executable");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod app");
    // If the relative executable were resolved at A, this decoy would fail loudly.
    let decoy = caller.join("app script.sh");
    fs::write(&decoy, "#!/bin/sh\nexit 49\n").expect("write decoy executable");
    fs::set_permissions(&decoy, fs::Permissions::from_mode(0o755)).expect("chmod decoy");
    fs::write(
        config_dir.join("config.yaml"),
        json!({
            "defaults": {"env": {"dotenv": [".env"], "envrc": false}},
            "workspaces": {
                "direct": {"path": workspace, "processes": [{"name": "app", "cmd": ["./app script.sh", "start"]}]},
                "wrapped": {"path": workspace, "processes": [{"name": "app", "cmd": ["/bin/sh", "-c", "exec './app script.sh' start-shell"]}]}
            }
        }).to_string(),
    )
    .expect("write config");

    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_wsx"))
            .args(args)
            .current_dir(&caller)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("WSX_LOG", "error")
            .stdin(Stdio::null())
            .output()
            .expect("run wsx outside workspace");
        assert!(
            output.status.success(),
            "wsx {args:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    };
    run(&["direct"]);
    run(&["exec", "./app script.sh", "exec tag 日本語"]);
    run(&["wrapped"]);
    run(&["exec", "/bin/sh", "-c", "exec './app script.sh' exec-shell"]);
    run(&["down"]);

    for tag in ["start", "exec tag 日本語", "start-shell", "exec-shell"] {
        assert_eq!(
            fs::read_to_string(workspace.join("output").join(format!("{tag}.txt")))
                .expect("read app output"),
            "{\"source\":\"B-workspace\"}\nB-workspace-asset\nB-workspace-env\n",
        );
        assert_eq!(
            fs::read_to_string(workspace.join("output").join(format!("child-{tag}.txt")))
                .expect("read nested child output"),
            "B-workspace-child\n",
        );
        for prefix in ["cwd-", "child-cwd-"] {
            assert_eq!(
                fs::read_to_string(workspace.join("output").join(format!("{prefix}{tag}.txt")))
                    .expect("read app cwd")
                    .trim(),
                workspace.to_string_lossy(),
            );
            assert!(
                !caller
                    .join("output")
                    .join(format!("{prefix}{tag}.txt"))
                    .exists()
            );
        }
        assert_eq!(
            fs::read_to_string(caller.join("output").join(format!("{tag}.txt")))
                .expect("read decoy output"),
            "untouched\n",
        );
        assert!(
            !caller
                .join("output")
                .join(format!("child-{tag}.txt"))
                .exists()
        );
    }
    assert_eq!(
        fs::read_to_string(caller.join("config.json")).unwrap(),
        "{\"source\":\"A-decoy\"}\n"
    );
    assert_eq!(
        fs::read_to_string(caller.join("assets/data.txt")).unwrap(),
        "A-decoy-asset\n"
    );
}
