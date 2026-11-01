#![cfg(target_os = "linux")]

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    outside: PathBuf,
    child_pids: Vec<u32>,
    reapers: RefCell<Vec<Child>>,
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
            reapers: RefCell::new(Vec::new()),
        }
    }

    fn run_raw(&self, args: &[&str]) -> Output {
        // Each invocation gets a dedicated Linux subreaper. It remains alive
        // after wsx exits and reaps its orphaned descendants, independently of
        // the host's PID 1. This is test infrastructure, not wsx behavior.
        let report = self.root.join(format!("result-{}.json", Uuid::new_v4()));
        let reaper = Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(
                r#"
import ctypes, json, os, pathlib, subprocess, sys
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
p = subprocess.Popen(sys.argv[2:], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate()
path = pathlib.Path(sys.argv[1])
tmp = path.with_suffix(".tmp")
tmp.write_text(json.dumps([p.returncode, list(out), list(err)]))
tmp.replace(path)
while True:
    try:
        os.waitpid(-1, 0)
    except ChildProcessError:
        break
"#,
            )
            .arg(&report)
            .arg(env!("CARGO_BIN_EXE_wsx"))
            .args(args)
            .current_dir(&self.outside)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("WSX_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start Python Linux subreaper fixture");
        self.reapers.borrow_mut().push(reaper);
        let deadline = Instant::now() + Duration::from_secs(35);
        while !report.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        let (code, stdout, stderr): (i32, Vec<u8>, Vec<u8>) = serde_json::from_slice(
            &fs::read(&report).expect("wsx invocation must finish within 35 seconds"),
        )
        .expect("parse invocation output");
        Output {
            status: ExitStatus::from_raw(if code < 0 { -code } else { code << 8 }),
            stdout,
            stderr,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let output = self.run_raw(args);
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
        // Killing managed children lets the dedicated reapers finish and reap
        // themselves via Child::wait, rather than leaking zombies to PID 1.
        for reaper in self.reapers.get_mut() {
            let deadline = Instant::now() + Duration::from_secs(3);
            while matches!(reaper.try_wait(), Ok(None)) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if matches!(reaper.try_wait(), Ok(None)) {
                let _ = reaper.kill();
            }
            let _ = reaper.wait();
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

fn wait_for_reaped(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while proc_state_and_group(pid).is_some() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        proc_state_and_group(pid).is_none(),
        "process {pid} was not reaped"
    );
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
    wait_for_reaped(root);
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
    wait_for_reaped(child);
    control.assert_running();
    assert_eq!(fixture.current()["status"], "stopped");
    fixture.run(&["down"]);

    fs::remove_file(fixture.workspace.join("child.pid")).expect("clear restart handshake");
    fixture.run(&["up"]);
    let restarted = fixture.remember_child();
    assert_ne!(fixture.current()["instance_id"], first_instance);
    assert!(is_live(restarted));
    fixture.run(&["down"]);
    wait_for_reaped(restarted);
    control.assert_running();
}

#[test]
fn exited_launcher_without_children_reconciles_to_stopped() {
    let fixture = Fixture::new(&["/bin/sh", "-c", "exit 0"]);
    fixture.run(&["demo"]);
    let root = fixture.root_pid();
    wait_for_reaped(root);
    let status = fixture.run(&["status"]);
    assert!(String::from_utf8_lossy(&status.stdout).contains("State: stopped"));
    assert_eq!(fixture.current()["status"], "stopped");
    fixture.run(&["down"]);
    fixture.run(&["down"]);
}

/// Holds an exited group leader unreaped until explicitly released. The
/// parent stays outside that group so wsx cannot kill the test's reaper.
struct UnreapedGroup {
    parent: Child,
    pid: u32,
}

impl UnreapedGroup {
    fn new() -> Self {
        let mut parent = Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(
                r#"
import os, sys
pid = os.fork()
if pid == 0:
    os.setpgid(0, 0)
    os._exit(0)
print(pid, flush=True)
sys.stdin.buffer.read(1)
os.waitpid(pid, 0)
"#,
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start controlled zombie parent");
        let mut line = String::new();
        BufReader::new(parent.stdout.take().expect("parent stdout"))
            .read_line(&mut line)
            .expect("read zombie pid");
        let pid = line.trim().parse().expect("numeric zombie pid");
        let group = Self { parent, pid };
        let deadline = Instant::now() + Duration::from_secs(3);
        while proc_state_and_group(pid) != Some(('Z', pid)) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(proc_state_and_group(pid), Some(('Z', pid)));
        group
    }
}

impl Drop for UnreapedGroup {
    fn drop(&mut self) {
        if let Some(mut stdin) = self.parent.stdin.take() {
            let _ = stdin.write_all(b"r");
        }
        let _ = self.parent.wait();
    }
}

#[test]
fn zombie_only_group_remains_running_and_failed_down_retains_metadata() {
    let fixture = Fixture::new(&["/bin/sh", "-c", "exit 0"]);
    fixture.run(&["demo"]);
    wait_for_reaped(fixture.root_pid());
    let original = fixture.current();
    let instance = original["instance_id"].as_str().expect("instance id");
    let metadata_path = fixture
        .home
        .join(".config/wsx/instances")
        .join(instance)
        .join("pids.json");
    let mut metadata: Value = serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
    let zombie = UnreapedGroup::new();
    metadata["entries"][0]["pid"] = json!(zombie.pid);
    fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    let saved_metadata = fs::read(&metadata_path).unwrap();

    let status = fixture.run(&["status"]);
    assert!(String::from_utf8_lossy(&status.stdout).contains("State: running"));
    let up = fixture.run(&["up"]);
    assert!(String::from_utf8_lossy(&up.stdout).contains("already running"));
    assert_eq!(fixture.current()["instance_id"], original["instance_id"]);

    let down = fixture.run_raw(&["down"]);
    assert!(
        !down.status.success(),
        "unreaped group must not report stopped"
    );
    let error = format!(
        "{}{}",
        String::from_utf8_lossy(&down.stdout),
        String::from_utf8_lossy(&down.stderr)
    );
    assert!(error.contains("failed to stop processes"), "{error}");
    assert!(
        error.contains("timed out; unable to confirm termination"),
        "{error}"
    );
    assert!(error.contains("runtime metadata preserved"), "{error}");
    let name = metadata["entries"][0]["name"].as_str().unwrap();
    assert!(
        error.contains(&format!("{name} (PGID {})", zombie.pid)),
        "{error}"
    );
    assert_eq!(fixture.current()["status"], "running");
    assert_eq!(fixture.current()["instance_id"], original["instance_id"]);
    assert_eq!(fs::read(&metadata_path).unwrap(), saved_metadata);
    assert_eq!(proc_state_and_group(zombie.pid), Some(('Z', zombie.pid)));
    let up_after_failure = fixture.run(&["up"]);
    assert!(String::from_utf8_lossy(&up_after_failure.stdout).contains("already running"));
    assert_eq!(fixture.current()["instance_id"], original["instance_id"]);
    assert_eq!(fs::read(&metadata_path).unwrap(), saved_metadata);

    let pid = zombie.pid;
    drop(zombie);
    wait_for_reaped(pid);
    fixture.run(&["down"]);
    assert_eq!(fixture.current()["status"], "stopped");
}
