#![cfg(target_os = "linux")]

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    outside: PathBuf,
    child_pids: Vec<u32>,
}

impl Fixture {
    fn new(command: &[&str]) -> Self {
        let root = std::env::temp_dir().join(format!("wsx-tree-lifecycle-{}", Uuid::new_v4()));
        let home = root.join("home");
        let workspace = root.join("workspace");
        let outside = root.join("outside");
        let config_dir = home.join(".config/wsx");
        for dir in [&config_dir, &workspace, &outside] {
            fs::create_dir_all(dir).expect("create isolated fixture");
        }
        fs::write(
            config_dir.join("config.yaml"),
            json!({
                "defaults": {"stop": {"grace_seconds": 0}, "env": {"dotenv": [], "envrc": false}},
                "workspaces": {"demo": {"path": workspace, "processes": [{"name": "launcher", "cmd": command}]}}
            })
            .to_string(),
        )
        .expect("write isolated config");
        Self {
            root,
            home,
            workspace,
            outside,
            child_pids: Vec::new(),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_wsx"))
            .args(args)
            .current_dir(&self.outside)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("WSX_LOG", "error")
            .stdin(Stdio::null())
            .output()
            .expect("run wsx");
        assert!(
            output.status.success(),
            "wsx {args:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn current(&self) -> Value {
        serde_json::from_str(
            &fs::read_to_string(self.home.join(".config/wsx/current.json"))
                .expect("read current state"),
        )
        .expect("parse current state")
    }

    fn root_pid(&self) -> u32 {
        let current = self.current();
        let instance = current["instance_id"].as_str().expect("instance id");
        let meta: Value = serde_json::from_str(
            &fs::read_to_string(
                self.home
                    .join(".config/wsx/instances")
                    .join(instance)
                    .join("pids.json"),
            )
            .expect("read pid metadata"),
        )
        .expect("parse pid metadata");
        u32::try_from(meta["entries"][0]["pid"].as_u64().expect("root pid")).expect("pid fits u32")
    }

    fn remember_child(&mut self) -> u32 {
        let pid = fs::read_to_string(self.workspace.join("child.pid"))
            .expect("child handshake")
            .trim()
            .parse()
            .expect("numeric child pid");
        self.child_pids.push(pid);
        pid
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // The marker also covers an assertion failure before remember_child().
        if let Ok(raw) = fs::read_to_string(self.workspace.join("child.pid"))
            && let Ok(pid) = raw.trim().parse::<u32>()
        {
            self.child_pids.push(pid);
        }
        for pid in &self.child_pids {
            // Only clean our known child while it still belongs to this fixture.
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

struct UnrelatedProcess(Child);

impl UnrelatedProcess {
    fn new(fixture: &Fixture) -> Self {
        let child = Command::new("/bin/sleep")
            .arg("60")
            .current_dir(&fixture.outside)
            .env_clear()
            .env("HOME", &fixture.home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("start unrelated control process in its own group");
        Self(child)
    }

    fn assert_running(&mut self) {
        assert!(
            self.0.try_wait().expect("check control process").is_none(),
            "wsx affected an unrelated process group"
        );
    }
}

impl Drop for UnrelatedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn proc_state_and_group(pid: u32) -> Option<(char, u32)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    Some((
        fields.first()?.chars().next()?,
        fields.get(2)?.parse().ok()?,
    ))
}

fn is_live(pid: u32) -> bool {
    proc_state_and_group(pid).is_some_and(|(state, _)| !matches!(state, 'Z' | 'X'))
}

fn wait_for_exit(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while is_live(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!is_live(pid), "synthetic child {pid} survived stop");
}

#[test]
fn exited_launcher_keeps_live_group_managed_through_status_up_and_down() {
    // SIG_IGN survives exec, so the orphaned sleep requires the force-stop path.
    // The handshake ensures the launcher cannot exit before the child is ready.
    let mut fixture = Fixture::new(&[
        "/bin/sh",
        "-c",
        "/bin/sh -c 'trap \"\" TERM; echo $$ > child.pid; exec /bin/sleep 60' & while [ ! -s child.pid ]; do /bin/sleep 0.01; done",
    ]);
    let mut control = UnrelatedProcess::new(&fixture);
    fixture.run(&["demo"]);
    let child = fixture.remember_child();
    let root = fixture.root_pid();
    let first_instance = fixture.current()["instance_id"].clone();
    assert_eq!(
        proc_state_and_group(control.0.id()).map(|(_, group)| group),
        Some(control.0.id()),
    );
    assert_ne!(control.0.id(), root);
    wait_for_exit(root);
    assert!(is_live(child));
    assert_eq!(
        proc_state_and_group(child).map(|(_, group)| group),
        Some(root)
    );

    let status = fixture.run(&["status"]);
    assert!(String::from_utf8_lossy(&status.stdout).contains("State: running"));
    assert_eq!(fixture.current()["status"], "running");
    control.assert_running();
    let up = fixture.run(&["up"]);
    assert!(String::from_utf8_lossy(&up.stdout).contains("already running"));
    assert_eq!(fixture.current()["instance_id"], first_instance);
    assert_eq!(fixture.remember_child(), child);
    control.assert_running();

    fixture.run(&["down"]);
    wait_for_exit(child);
    control.assert_running();
    assert_eq!(fixture.current()["status"], "stopped");
    fixture.run(&["down"]);

    fs::remove_file(fixture.workspace.join("child.pid")).expect("clear restart handshake");
    fixture.run(&["up"]);
    let restarted = fixture.remember_child();
    assert_ne!(fixture.current()["instance_id"], first_instance);
    assert!(is_live(restarted));
    fixture.run(&["down"]);
    wait_for_exit(restarted);
    control.assert_running();
}

#[test]
fn exited_launcher_without_children_reconciles_to_stopped() {
    let fixture = Fixture::new(&["/bin/sh", "-c", "exit 0"]);
    fixture.run(&["demo"]);
    let root = fixture.root_pid();
    wait_for_exit(root);
    let status = fixture.run(&["status"]);
    assert!(String::from_utf8_lossy(&status.stdout).contains("State: stopped"));
    assert_eq!(fixture.current()["status"], "stopped");
    fixture.run(&["down"]);
    fixture.run(&["down"]);
}
