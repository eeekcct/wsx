#![cfg(target_os = "linux")]

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    owned_pids: Vec<u32>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("wsx-metadata-errors-{}", Uuid::new_v4()));
        let home = root.join("home");
        let workspace = root.join("workspace");
        fs::create_dir_all(home.join(".config/wsx")).expect("create isolated home");
        fs::create_dir_all(&workspace).expect("create isolated workspace");
        fs::write(
            home.join(".config/wsx/config.yaml"),
            json!({
                "defaults": {"stop": {"grace_seconds": 0}, "env": {"dotenv": [], "envrc": false}},
                "workspaces": {
                    "demo": {"path": workspace, "processes": [
                        {"name": "short", "cmd": ["/bin/true"]},
                        {"name": "sleeper", "cmd": ["/bin/sleep", "60"]}
                    ]},
                    "other": {"path": workspace, "processes": [{"cmd": ["/bin/true"]}]}
                }
            })
            .to_string(),
        )
        .expect("write config");
        Self {
            root,
            home,
            workspace,
            owned_pids: Vec::new(),
        }
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

    fn start_and_remember_pids(&mut self) -> PathBuf {
        assert_success(&self.run(&["demo"]));
        let current: Value =
            serde_json::from_slice(&fs::read(self.current_path()).expect("read current state"))
                .expect("parse current state");
        let path = self
            .home
            .join(".config/wsx/instances")
            .join(current["instance_id"].as_str().expect("instance id"))
            .join("pids.json");
        let pids: Value =
            serde_json::from_slice(&fs::read(&path).expect("read pids")).expect("parse pids");
        self.owned_pids = pids["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| u32::try_from(entry["pid"].as_u64().expect("pid")).expect("pid fits"))
            .collect();
        assert!(self.owned_pids.iter().any(|pid| is_live(*pid)));
        path
    }

    fn assert_commands_fail_without_changing_current(&self) {
        let before = fs::read(self.current_path()).expect("read malformed current state");
        for args in [
            vec!["status"],
            vec!["logs", "--no-follow"],
            vec!["up"],
            vec!["down"],
            vec!["select", "other"],
            vec!["other"],
            vec!["exec", "/bin/true"],
        ] {
            let output = self.run(&args);
            assert_eq!(
                output.status.code(),
                Some(1),
                "wsx {args:?} must fail closed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            assert_eq!(
                fs::read(self.current_path()).expect("state must remain available for repair"),
                before,
                "wsx {args:?} mutated uncertain state",
            );
            assert!(
                self.owned_pids.iter().any(|pid| is_live(*pid)),
                "wsx {args:?} signaled a process without valid tracking metadata",
            );
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for pid in &self.owned_pids {
            if fs::read_link(format!("/proc/{pid}/cwd")).ok().as_deref()
                == Some(self.workspace.as_path())
                && let Ok(raw_pid) = i32::try_from(*pid)
            {
                let _ = kill(Pid::from_raw(raw_pid), Signal::SIGKILL);
            }
        }
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

fn is_live(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| stat.rsplit_once(") ").map(|(_, rest)| rest.chars().next()))
        .flatten()
        .is_some_and(|state| !matches!(state, 'Z' | 'X'))
}

#[test]
fn corrupt_current_is_preserved_and_never_reported_as_stopped() {
    let mut fixture = Fixture::new();
    fixture.start_and_remember_pids();
    let original = fs::read(fixture.current_path()).expect("save current state for repair");
    fs::write(fixture.current_path(), b"{broken").expect("corrupt own fixture state");
    fixture.assert_commands_fail_without_changing_current();
    fs::write(fixture.current_path(), original).expect("restore original tracking metadata");
    assert_success(&fixture.run(&["down"]));
    assert!(fixture.owned_pids.iter().all(|pid| !is_live(*pid)));
}

#[test]
fn corrupt_or_missing_pids_preserve_instance_and_prevent_duplicate_start() {
    for missing in [false, true] {
        let mut fixture = Fixture::new();
        let path = fixture.start_and_remember_pids();
        let original = fs::read(&path).expect("save pid metadata for repair");
        if missing {
            fs::remove_file(&path).expect("remove own fixture pid metadata");
        } else {
            fs::write(&path, b"{broken").expect("corrupt own fixture pid metadata");
        }
        fixture.assert_commands_fail_without_changing_current();
        if missing {
            assert!(
                !path.exists(),
                "failed commands must not fabricate metadata"
            );
        } else {
            assert_eq!(fs::read(&path).expect("preserved metadata"), b"{broken");
        }
        fs::write(&path, original).expect("restore original tracking metadata");
        assert_success(&fixture.run(&["down"]));
        assert!(fixture.owned_pids.iter().all(|pid| !is_live(*pid)));
    }
}

#[test]
fn running_state_without_instance_id_requires_repair() {
    let mut fixture = Fixture::new();
    fixture.start_and_remember_pids();
    let original = fs::read(fixture.current_path()).expect("save current state for repair");
    let mut broken: Value = serde_json::from_slice(&original).expect("current json");
    broken["instance_id"] = Value::Null;
    fs::write(fixture.current_path(), broken.to_string()).expect("remove instance pointer");
    fixture.assert_commands_fail_without_changing_current();
    fs::write(fixture.current_path(), original).expect("restore original tracking metadata");
    assert_success(&fixture.run(&["down"]));
}

#[test]
fn inconsistent_pid_metadata_preserves_state_and_never_signals_processes() {
    for corruption in [
        "empty",
        "instance",
        "workspace",
        "pid-zero",
        "pid-one",
        "pid-overflow",
    ] {
        let mut fixture = Fixture::new();
        let path = fixture.start_and_remember_pids();
        let original = fs::read(&path).expect("save pid metadata for repair");
        let mut broken: Value = serde_json::from_slice(&original).expect("pid metadata");
        match corruption {
            "empty" => broken["entries"] = json!([]),
            "instance" => broken["instance_id"] = json!("wrong-instance"),
            "workspace" => broken["workspace"] = json!("wrong-workspace"),
            "pid-zero" => broken["entries"][0]["pid"] = json!(0),
            "pid-one" => broken["entries"][0]["pid"] = json!(1),
            "pid-overflow" => broken["entries"][0]["pid"] = json!(u32::MAX),
            _ => unreachable!(),
        }
        let broken_bytes = broken.to_string();
        fs::write(&path, &broken_bytes).expect("write inconsistent pid metadata");
        fixture.assert_commands_fail_without_changing_current();
        assert_eq!(fs::read_to_string(&path).unwrap(), broken_bytes);
        fs::write(&path, original).expect("restore original tracking metadata");
        assert_success(&fixture.run(&["down"]));
        assert!(fixture.owned_pids.iter().all(|pid| !is_live(*pid)));
    }
}

#[test]
fn absent_current_state_still_allows_status_and_down_noops() {
    let fixture = Fixture::new();
    assert_success(&fixture.run(&["status"]));
    assert_success(&fixture.run(&["down"]));
    assert!(!fixture.current_path().exists());
}

struct DirectoryPermissionsGuard {
    path: PathBuf,
    original: fs::Permissions,
}

impl DirectoryPermissionsGuard {
    fn deny_access(path: PathBuf) -> Self {
        let original = fs::metadata(&path)
            .expect("read fixture permissions")
            .permissions();
        let guard = Self { path, original };
        fs::set_permissions(&guard.path, fs::Permissions::from_mode(0o000))
            .expect("deny access to isolated state directory");
        guard
    }
}

impl Drop for DirectoryPermissionsGuard {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.path, self.original.clone());
    }
}

#[test]
fn inaccessible_current_state_is_not_mistaken_for_absent_state() {
    let fixture = Fixture::new();
    assert_success(&fixture.run(&["select", "demo"]));
    let original = fs::read(fixture.current_path()).expect("save readable current state");
    let permissions = DirectoryPermissionsGuard::deny_access(fixture.home.join(".config/wsx"));
    match fs::read_to_string(fixture.current_path()) {
        Ok(_) => {
            // Effective root (or equivalent capability) can bypass Unix mode bits.
            // Restore through the guard and skip only this permission-specific check.
            eprintln!("state remains readable with mode 000; skipping permission assertion");
            return;
        }
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied),
    }
    for args in [&["status"][..], &["down"][..]] {
        let output = fixture.run(args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "wsx {args:?} must not treat inaccessible state as absent: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("failed to read"));
    }
    drop(permissions);
    assert_eq!(
        fs::read(fixture.current_path()).expect("state restored"),
        original
    );
    assert_success(&fixture.run(&["status"]));
    assert_success(&fixture.run(&["down"]));
}
