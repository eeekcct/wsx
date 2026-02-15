use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

pub fn apply_spawn_settings(command: &mut Command) {
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

pub fn send_graceful(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T"])
        .status();
}

pub fn send_force(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status();
}
