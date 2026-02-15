use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

pub fn send_graceful(pid: u32) {
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
}

pub fn send_force(pid: u32) {
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
}
