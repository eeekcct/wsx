use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const TASKKILL_GRACE_TIMEOUT_MS: u64 = 1500;
const TASKKILL_FORCE_TIMEOUT_MS: u64 = 4000;
const TASKKILL_POLL_INTERVAL_MS: u64 = 50;

pub fn apply_spawn_settings(command: &mut Command) {
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

pub fn send_graceful(pid: u32) {
    let _ = run_taskkill(
        &["/PID", &pid.to_string(), "/T"],
        Duration::from_millis(TASKKILL_GRACE_TIMEOUT_MS),
    );
}

pub fn send_force(pid: u32) {
    let timeout = Duration::from_millis(TASKKILL_FORCE_TIMEOUT_MS);
    let tree_killed = run_taskkill(&["/PID", &pid.to_string(), "/T", "/F"], timeout);
    if tree_killed {
        return;
    }

    // `/T` can fail when some descendants are protected, but the parent
    // process may still be terminable.
    let parent_killed = run_taskkill(&["/PID", &pid.to_string(), "/F"], timeout);
    if !parent_killed {
        let _ = run_stop_process_force(pid, timeout);
    }
}

fn run_taskkill(args: &[&str], timeout: Duration) -> bool {
    run_quiet_command_with_timeout("taskkill", args, timeout)
}

fn run_stop_process_force(pid: u32, timeout: Duration) -> bool {
    let script = format!(
        "try {{ Stop-Process -Id {pid} -Force -ErrorAction Stop; exit 0 }} catch {{ exit 1 }}"
    );

    run_quiet_command_with_timeout(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ],
        timeout,
    ) || run_quiet_command_with_timeout(
        "pwsh",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        timeout,
    )
}

fn run_quiet_command_with_timeout(program: &str, args: &[&str], timeout: Duration) -> bool {
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return false,
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                thread::sleep(Duration::from_millis(TASKKILL_POLL_INTERVAL_MS));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}
