use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("wsx-concurrent-{}", Uuid::new_v4()));
        fs::create_dir_all(root.join("home/.config/wsx")).unwrap();
        fs::create_dir_all(root.join("project")).unwrap();
        let fixture = Self { root };
        let service = "import pathlib,time; pathlib.Path('started').touch(); time.sleep(2)";
        fs::write(
            fixture.root.join("home/.config/wsx/config.yaml"),
            json!({
                "defaults": {"env": {"dotenv": [], "envrc": false}, "stop": {"grace_seconds": 1}},
                "workspaces": {
                    "demo": {"path": fixture.root.join("project"), "env": {"envrc": true},
                        "processes": [{"name": "service", "cmd": [python(), "-c", service]}]},
                    "other": {"path": fixture.root.join("project"),
                        "processes": [{"name": "service", "cmd": [python(), "-c", service]}]}
                }
            })
            .to_string(),
        )
        .unwrap();
        // The handshake puts the first up inside its read/start transaction.
        fs::write(
            fixture.root.join("project/.envrc"),
            "echo ready > entered\nn=0\nwhile [ ! -f release ]; do n=$((n + 1)); [ \"$n\" -lt 500 ] || exit 1; sleep 0.02; done\necho done > envrc-finished\n",
        )
        .unwrap();
        fixture.run(&["select", "demo"]);
        fixture
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wsx"));
        command
            .args(args)
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env_remove("WSX_HOME")
            .env("WSX_LOG", "off")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn spawn(&self, args: &[&str]) -> Child {
        self.command(args).spawn().expect("spawn wsx")
    }

    fn run(&self, args: &[&str]) -> Output {
        finish(self.spawn(args))
    }

    fn wait_for(&self, name: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.root.join("project").join(name).exists() {
            assert!(Instant::now() < deadline, "missing handshake {name}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn release(&self) {
        fs::write(self.root.join("project/release"), "go").unwrap();
    }

    fn current(&self) -> Value {
        serde_json::from_slice(&fs::read(self.root.join("home/.config/wsx/current.json")).unwrap())
            .unwrap()
    }

    fn instances(&self) -> usize {
        fs::read_dir(self.root.join("home/.config/wsx/instances"))
            .unwrap()
            .count()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Also release envrc on assertion failure; fixture services are finite.
        let _ = fs::write(self.root.join("project/release"), "go");
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn python() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
}

fn finish(child: Child) -> Output {
    finish_within(child, Duration::from_secs(15))
}

fn finish_within(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("wsx did not finish: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "wsx failed: {output:?}");
    output
}

#[test]
fn concurrent_up_starts_only_one_instance() {
    let fixture = Fixture::new();
    let first = fixture.spawn(&["up"]);
    fixture.wait_for("entered");
    let mut second = fixture.spawn(&["up"]);
    thread::sleep(Duration::from_millis(150));
    assert!(second.try_wait().unwrap().is_none());
    fixture.release();
    let first = finish(first);
    let second = finish(second);
    assert!(String::from_utf8_lossy(&first.stdout).contains("started workspace"));
    assert!(String::from_utf8_lossy(&second.stdout).contains("already running"));
    assert_eq!(fixture.instances(), 1);
    fixture.run(&["status"]);
    assert_eq!(fixture.current()["status"], "stopped");
}

#[test]
fn down_and_select_wait_for_startup_but_not_log_follow() {
    for operation in [&["down"][..], &["select", "other"][..]] {
        let fixture = Fixture::new();
        let config = fixture.root.join("home/.config/wsx/config.yaml");
        let raw = fs::read_to_string(&config)
            .unwrap()
            .replace("time.sleep(2)", "time.sleep(10)");
        fs::write(config, raw).unwrap();
        let first = fixture.spawn(&["up"]);
        fixture.wait_for("entered");
        let mut next = fixture.spawn(operation);
        thread::sleep(Duration::from_millis(150));
        assert!(
            next.try_wait().unwrap().is_none(),
            "{operation:?} passed startup transaction"
        );
        fixture.release();
        // A lock held through follow would wait for the ten-second service.
        finish_within(next, Duration::from_secs(5));
        finish(first);
        assert_eq!(fixture.instances(), 1);
        assert_eq!(fixture.current()["status"], "stopped");
        assert_eq!(
            fixture.current()["workspace"],
            if operation[0] == "select" {
                "other"
            } else {
                "demo"
            }
        );
    }
}

#[test]
fn different_state_roots_do_not_block_each_other() {
    let first = Fixture::new();
    let second = Fixture::new();
    let pending = first.spawn(&["up"]);
    first.wait_for("entered");
    second.run(&["select", "other"]);
    assert_eq!(second.current()["workspace"], "other");
    first.release();
    finish(pending);
}

#[test]
fn long_exec_releases_lifecycle_lock_before_waiting() {
    let fixture = Fixture::new();
    fixture.release();
    let mut exec = fixture.spawn(&[
        "exec",
        python(),
        "-c",
        "import pathlib,time; pathlib.Path('executing').touch(); time.sleep(2)",
    ]);
    fixture.wait_for("executing");
    fixture.run(&["select", "other"]);
    assert!(
        exec.try_wait().unwrap().is_none(),
        "select waited for exec completion"
    );
    finish(exec);
}

#[test]
fn killed_startup_releases_lock_without_inheriting_it_to_envrc() {
    let fixture = Fixture::new();
    let mut up = fixture.spawn(&["up"]);
    fixture.wait_for("entered");
    up.kill().unwrap();
    up.wait().unwrap();
    // envrc is still waiting: an inherited lock would deadlock this selection.
    fixture.run(&["select", "other"]);
    fixture.release();
    fixture.wait_for("envrc-finished");
    assert_eq!(fixture.current()["workspace"], "other");
    assert_eq!(fixture.current()["status"], "stopped");
}

#[test]
fn failed_startup_releases_lifecycle_lock() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("project/.envrc"), "exit 13\n").unwrap();
    let output = fixture.command(&["up"]).output().unwrap();
    assert!(!output.status.success(), "envrc failure must fail startup");
    fixture.run(&["select", "other"]);
    assert_eq!(fixture.current()["workspace"], "other");
    assert_eq!(fixture.current()["status"], "stopped");
}

#[cfg(target_os = "linux")]
#[test]
fn interrupted_old_follower_does_not_stop_replacement_instance() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    // A stopped test follower must not survive an assertion failure.
    struct Follower(Child);
    impl Drop for Follower {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let fixture = Fixture::new();
    let config = fixture.root.join("home/.config/wsx/config.yaml");
    let raw = fs::read_to_string(&config)
        .unwrap()
        .replace("time.sleep(2)", "time.sleep(10)");
    fs::write(config, raw).unwrap();
    fixture.release();
    let original = fixture.spawn(&["up"]);
    fixture.wait_for("started");
    let mut follower = Follower(fixture.spawn(&["logs"]));
    let pid = Pid::from_raw(i32::try_from(follower.0.id()).unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    // Wait for the actual SIGINT handler, not a scheduling-dependent sleep.
    loop {
        let status = fs::read_to_string(format!("/proc/{}/status", pid.as_raw())).unwrap();
        let caught = status
            .lines()
            .find_map(|line| line.strip_prefix("SigCgt:\t"))
            .and_then(|mask| u64::from_str_radix(mask, 16).ok())
            .unwrap();
        if caught & 2 != 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "log follower did not install SIGINT handler"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let original_id = fixture.current()["instance_id"].clone();
    assert!(original_id.is_string());
    kill(pid, Signal::SIGSTOP).unwrap();
    // Keep original up running so it can reap its service during the switch.
    let replacement = fixture.spawn(&["other"]);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let current = fixture.current();
        if current["workspace"] == "other" && current["status"] == "running" {
            break;
        }
        assert!(Instant::now() < deadline, "replacement did not start");
        thread::sleep(Duration::from_millis(10));
    }
    let replacement_id = fixture.current()["instance_id"].clone();
    assert_ne!(replacement_id, original_id);
    kill(pid, Signal::SIGINT).unwrap();
    kill(pid, Signal::SIGCONT).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = follower.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "interrupted follower did not exit"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(130));
    fixture.run(&["status"]);
    assert_eq!(fixture.current()["instance_id"], replacement_id);
    assert_eq!(fixture.current()["status"], "running");
    finish(original);
    fixture.run(&["down"]);
    finish(replacement);
}
