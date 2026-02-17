use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessStatus, System};

use crate::config::ResolvedWorkspace;
use crate::paths;
use crate::state::{PidEntry, PidsFile};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub fn start_workspace(
    workspace: &ResolvedWorkspace,
    instance_id: &str,
    env_map: &HashMap<String, String>,
) -> Result<PidsFile> {
    let instance_dir = paths::instance_dir(instance_id)?;
    let logs_dir = paths::logs_dir(instance_id)?;

    fs::create_dir_all(&instance_dir)
        .with_context(|| format!("failed to create {}", instance_dir.display()))?;
    fs::create_dir_all(&logs_dir)
        .with_context(|| format!("failed to create {}", logs_dir.display()))?;

    let mut entries = Vec::with_capacity(workspace.processes.len());

    for process in &workspace.processes {
        let out_path = logs_dir.join(format!("{}.out.log", process.name));
        let err_path = logs_dir.join(format!("{}.err.log", process.name));
        let combined_path = logs_dir.join(format!("{}.combined.log", process.name));

        let out_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&out_path)
            .with_context(|| format!("failed to open {}", out_path.display()))?;

        let err_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&err_path)
            .with_context(|| format!("failed to open {}", err_path.display()))?;

        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&combined_path)
            .with_context(|| format!("failed to open {}", combined_path.display()))?;

        let mut command = Command::new(&process.cmd[0]);
        command
            .args(&process.cmd[1..])
            .current_dir(&workspace.path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_file))
            .stderr(Stdio::from(err_file))
            .env_clear()
            .envs(env_map.iter());

        apply_spawn_settings(&mut command);

        let child = command.spawn().with_context(|| {
            format!(
                "failed to start process `{}` using command {:?}",
                process.name, process.cmd
            )
        });

        let child = match child {
            Ok(child) => child,
            Err(err) => {
                let partial = PidsFile {
                    workspace: workspace.name.clone(),
                    instance_id: instance_id.to_string(),
                    entries,
                };
                if !partial.entries.is_empty() {
                    let _ = stop_workspace(&partial, workspace.grace_seconds);
                }
                return Err(err);
            }
        };

        entries.push(PidEntry {
            name: process.name.clone(),
            pid: child.id(),
            out_log: out_path.to_string_lossy().to_string(),
            err_log: err_path.to_string_lossy().to_string(),
            combined_log: combined_path.to_string_lossy().to_string(),
        });
    }

    Ok(PidsFile {
        workspace: workspace.name.clone(),
        instance_id: instance_id.to_string(),
        entries,
    })
}

pub fn stop_workspace(pids_file: &PidsFile, grace_seconds: u64) -> Result<()> {
    for entry in &pids_file.entries {
        send_graceful_stop(entry.pid);
    }

    let deadline = Instant::now() + Duration::from_secs(grace_seconds);
    while Instant::now() < deadline {
        if running_entries(pids_file).is_empty() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }

    for entry in &pids_file.entries {
        if is_pid_running(entry.pid) {
            send_force_stop(entry.pid);
        }
    }

    let force_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < force_deadline {
        if running_entries(pids_file).is_empty() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }

    let remaining = running_entries(pids_file);
    if !remaining.is_empty() {
        let details = remaining
            .into_iter()
            .map(|entry| format!("{} (pid {})", entry.name, entry.pid))
            .collect::<Vec<_>>()
            .join(", ");
        bail!("failed to stop processes: {details}");
    }

    Ok(())
}

fn running_entries<'a>(pids_file: &'a PidsFile) -> Vec<&'a PidEntry> {
    pids_file
        .entries
        .iter()
        .filter(|entry| is_pid_running(entry.pid))
        .collect()
}

pub fn is_pid_running(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_all();
    match system.process(Pid::from_u32(pid)) {
        Some(process) => !matches!(
            process.status(),
            ProcessStatus::Zombie | ProcessStatus::Dead
        ),
        None => false,
    }
}

#[cfg(unix)]
fn apply_spawn_settings(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
fn apply_spawn_settings(command: &mut Command) {
    windows::apply_spawn_settings(command);
}

#[cfg(unix)]
fn send_graceful_stop(pid: u32) {
    unix::send_graceful(pid);
}

#[cfg(windows)]
fn send_graceful_stop(pid: u32) {
    windows::send_graceful(pid);
}

#[cfg(unix)]
fn send_force_stop(pid: u32) {
    unix::send_force(pid);
}

#[cfg(windows)]
fn send_force_stop(pid: u32) {
    windows::send_force(pid);
}
