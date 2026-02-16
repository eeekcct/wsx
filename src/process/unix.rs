use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

pub fn send_graceful(pid: u32) {
    if let Some(group_pid) = process_group_pid(pid) {
        let _ = kill(group_pid, Signal::SIGTERM);
    }
}

pub fn send_force(pid: u32) {
    if let Some(group_pid) = process_group_pid(pid) {
        let _ = kill(group_pid, Signal::SIGKILL);
    }
}

fn process_group_pid(pid: u32) -> Option<Pid> {
    let raw_pid = i32::try_from(pid).ok()?;
    Some(Pid::from_raw(-raw_pid))
}
