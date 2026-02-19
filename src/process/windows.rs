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
    send_force_with_runner(pid, timeout, run_taskkill);
}

fn run_taskkill(args: &[&str], timeout: Duration) -> bool {
    run_quiet_command_with_timeout("taskkill", args, timeout)
}

fn send_force_with_runner<F>(pid: u32, timeout: Duration, mut run_taskkill_cmd: F)
where
    F: FnMut(&[&str], Duration) -> bool,
{
    let pid = pid.to_string();
    let _ = run_taskkill_cmd(&["/PID", &pid, "/T", "/F"], timeout);
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

#[cfg(test)]
mod tests {
    use super::send_force_with_runner;
    use std::time::Duration;

    #[test]
    fn force_stop_uses_single_tree_kill_attempt() {
        let mut calls = Vec::new();
        send_force_with_runner(1234, Duration::from_millis(1), |args, _timeout| {
            calls.push(args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>());
            false
        });

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], vec!["/PID", "1234", "/T", "/F"]);
    }
}
