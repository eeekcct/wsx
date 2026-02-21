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

const POLL_INTERVAL_MS: u64 = 200;
const FORCE_STOP_TIMEOUT_SECS: u64 = 20;
const FORCE_RETRY_INTERVAL_SECS: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForceStopError {
    pid: u32,
    message: String,
}

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

        let mut child = match child {
            Ok(child) => child,
            Err(err) => {
                cleanup_partial_entries(workspace, instance_id, &entries);
                return Err(err);
            }
        };

        let windows_job_name = match attach_process_tracking(instance_id, &process.name, &child) {
            Ok(value) => value,
            Err(err) => {
                let pid = child.id();
                rollback_untracked_child(&mut child);
                cleanup_partial_entries(workspace, instance_id, &entries);
                bail!(
                    "failed to attach process `{}` (pid {}) to tracking: {err:#}",
                    process.name,
                    pid
                );
            }
        };

        entries.push(PidEntry {
            name: process.name.clone(),
            pid: child.id(),
            out_log: out_path.to_string_lossy().to_string(),
            err_log: err_path.to_string_lossy().to_string(),
            combined_log: combined_path.to_string_lossy().to_string(),
            windows_job_name,
        });
    }

    Ok(PidsFile {
        workspace: workspace.name.clone(),
        instance_id: instance_id.to_string(),
        entries,
    })
}

fn cleanup_partial_entries(workspace: &ResolvedWorkspace, instance_id: &str, entries: &[PidEntry]) {
    if entries.is_empty() {
        return;
    }

    let partial = PidsFile {
        workspace: workspace.name.clone(),
        instance_id: instance_id.to_string(),
        entries: entries.to_vec(),
    };
    let _ = stop_workspace(&partial, workspace.grace_seconds);
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
        thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }

    let force_deadline = Instant::now() + Duration::from_secs(FORCE_STOP_TIMEOUT_SECS);
    let mut next_force_attempt_at = Instant::now();
    while Instant::now() < force_deadline {
        let running = running_entries(pids_file);
        if running.is_empty() {
            return Ok(());
        }

        if Instant::now() >= next_force_attempt_at {
            // Try force-stop for every running entry in this snapshot before
            // deciding whether this attempt should fail.
            let force_errors = collect_force_stop_errors(running, force_stop_entry);
            validate_force_errors_with(force_errors, is_pid_running)?;
            next_force_attempt_at = Instant::now() + Duration::from_secs(FORCE_RETRY_INTERVAL_SECS);
        }

        thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
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

fn force_stop_entry(entry: &PidEntry) -> Result<()> {
    force_stop_entry_with(entry, send_force_stop, is_pid_running)
}

fn collect_force_stop_errors<'a, I, F>(
    running: I,
    mut force_stop_entry_fn: F,
) -> Vec<ForceStopError>
where
    I: IntoIterator<Item = &'a PidEntry>,
    F: FnMut(&PidEntry) -> Result<()>,
{
    let mut errors = Vec::new();
    for entry in running {
        if let Err(err) = force_stop_entry_fn(entry) {
            errors.push(ForceStopError {
                pid: entry.pid,
                message: format!("{} (pid {}): {err:#}", entry.name, entry.pid),
            });
        }
    }
    errors
}

fn validate_force_errors_with<F>(
    force_errors: Vec<ForceStopError>,
    mut is_pid_running_fn: F,
) -> Result<()>
where
    F: FnMut(u32) -> bool,
{
    if force_errors.is_empty() {
        return Ok(());
    }

    let remaining_errors = force_errors
        .into_iter()
        .filter(|error| is_pid_running_fn(error.pid))
        .map(|error| error.message)
        .collect::<Vec<_>>();

    if remaining_errors.is_empty() {
        // All failed PIDs are now gone, so earlier per-process errors were transient.
        return Ok(());
    }

    bail!(
        "failed to force stop processes: {}",
        remaining_errors.join("; ")
    );
}

fn rollback_untracked_child(child: &mut std::process::Child) {
    rollback_untracked_pid(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

fn rollback_untracked_pid(pid: u32) {
    rollback_untracked_pid_with(
        pid,
        send_graceful_stop,
        is_pid_running,
        force_stop_untracked_pid,
    );
}

fn rollback_untracked_pid_with<FGraceful, FRunning, FForce>(
    pid: u32,
    mut send_graceful_stop_fn: FGraceful,
    mut is_pid_running_fn: FRunning,
    mut force_stop_pid_tree_fn: FForce,
) where
    FGraceful: FnMut(u32),
    FRunning: FnMut(u32) -> bool,
    FForce: FnMut(u32),
{
    send_graceful_stop_fn(pid);
    if is_pid_running_fn(pid) {
        force_stop_pid_tree_fn(pid);
    }
}

fn force_stop_entry_with<FStop, FRunning>(
    entry: &PidEntry,
    mut send_force_stop_fn: FStop,
    mut is_pid_running_fn: FRunning,
) -> Result<()>
where
    FStop: FnMut(&PidEntry) -> Result<()>,
    FRunning: FnMut(u32) -> bool,
{
    match send_force_stop_fn(entry) {
        Ok(()) => Ok(()),
        Err(err) => {
            if !is_pid_running_fn(entry.pid) {
                // Process exited between snapshot and force-stop attempt.
                return Ok(());
            }
            Err(err).with_context(|| {
                format!(
                    "failed to force stop process `{}` (pid {})",
                    entry.name, entry.pid
                )
            })
        }
    }
}

fn running_entries(pids_file: &PidsFile) -> Vec<&PidEntry> {
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
fn attach_process_tracking(
    _instance_id: &str,
    _process_name: &str,
    _child: &std::process::Child,
) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(windows)]
fn attach_process_tracking(
    instance_id: &str,
    process_name: &str,
    child: &std::process::Child,
) -> Result<Option<String>> {
    windows::attach_to_job(instance_id, process_name, child).map(Some)
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
fn send_force_stop(entry: &PidEntry) -> Result<()> {
    unix::send_force(entry.pid);
    Ok(())
}

#[cfg(windows)]
fn send_force_stop(entry: &PidEntry) -> Result<()> {
    windows::send_force(entry)
}

#[cfg(unix)]
fn force_stop_untracked_pid(pid: u32) {
    unix::send_force(pid);
}

#[cfg(windows)]
fn force_stop_untracked_pid(pid: u32) {
    windows::force_stop_tree(pid);
}

#[cfg(test)]
mod tests {
    use super::{
        ForceStopError, collect_force_stop_errors, force_stop_entry_with,
        rollback_untracked_pid_with, validate_force_errors_with,
    };
    use crate::state::PidEntry;
    use anyhow::{Result, anyhow};
    use std::cell::{Cell, RefCell};

    fn sample_entry() -> PidEntry {
        PidEntry {
            name: "tree".to_string(),
            pid: 12345,
            out_log: "out.log".to_string(),
            err_log: "err.log".to_string(),
            combined_log: "combined.log".to_string(),
            windows_job_name: Some(r"Global\wsx-demo-tree-12345".to_string()),
        }
    }

    #[test]
    fn force_stop_error_is_ignored_when_pid_already_exited() {
        let entry = sample_entry();
        let result =
            force_stop_entry_with(&entry, |_entry| Err(anyhow!("job not found")), |_pid| false);
        assert!(
            result.is_ok(),
            "race-condition error should be ignored when pid already exited"
        );
    }

    #[test]
    fn force_stop_error_is_returned_when_pid_still_running() {
        let entry = sample_entry();
        let result = force_stop_entry_with(
            &entry,
            |_entry| Err(anyhow!("permission denied")),
            |_pid| true,
        );
        assert!(
            result.is_err(),
            "error should be returned when pid is alive"
        );
        let err_text = format!("{:#}", result.expect_err("expected force-stop failure"));
        assert!(
            err_text.contains("failed to force stop process `tree` (pid 12345)"),
            "unexpected error text: {err_text}"
        );
    }

    #[test]
    fn force_stop_success_does_not_recheck_liveness() -> Result<()> {
        let entry = sample_entry();
        let liveness_checks = Cell::new(0usize);
        force_stop_entry_with(
            &entry,
            |_entry| Ok(()),
            |_pid| {
                liveness_checks.set(liveness_checks.get() + 1);
                true
            },
        )?;
        assert_eq!(
            liveness_checks.get(),
            0,
            "liveness should not be checked on successful force-stop"
        );
        Ok(())
    }

    #[test]
    fn force_stop_attempts_all_entries_before_returning_errors() {
        let a = sample_entry();
        let mut b = sample_entry();
        b.name = "web".to_string();
        b.pid = 22334;
        let mut c = sample_entry();
        c.name = "worker".to_string();
        c.pid = 33445;

        let called = RefCell::new(Vec::new());
        let errors = collect_force_stop_errors(vec![&a, &b, &c], |entry| {
            called.borrow_mut().push(entry.pid);
            if entry.pid == 22334 {
                Err(anyhow!("blocked"))
            } else {
                Ok(())
            }
        });

        assert_eq!(*called.borrow(), vec![12345, 22334, 33445]);
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].message.contains("web (pid 22334)"),
            "unexpected error list: {errors:?}"
        );
    }

    fn force_error(pid: u32, message: &str) -> ForceStopError {
        ForceStopError {
            pid,
            message: message.to_string(),
        }
    }

    #[test]
    fn validate_force_errors_ignores_transient_errors_for_exited_failed_pid() -> Result<()> {
        validate_force_errors_with(
            vec![force_error(22334, "web (pid 22334): blocked")],
            |_pid| false,
        )
    }

    #[test]
    fn validate_force_errors_fails_when_failed_pid_still_running() {
        let result = validate_force_errors_with(
            vec![
                force_error(22334, "web (pid 22334): blocked"),
                force_error(12345, "tree (pid 12345): denied"),
            ],
            |pid| pid == 22334,
        );
        assert!(result.is_err(), "expected validation failure");
        let message = format!("{:#}", result.expect_err("expected force-stop error"));
        assert!(
            message.contains("failed to force stop processes:"),
            "unexpected error text: {message}"
        );
        assert!(
            message.contains("web (pid 22334): blocked"),
            "missing first aggregated error: {message}"
        );
        assert!(
            !message.contains("tree (pid 12345): denied"),
            "errors for already-exited failed pid should be dropped: {message}"
        );
    }

    #[test]
    fn rollback_untracked_pid_uses_force_only_when_still_running() {
        let graceful_calls = RefCell::new(Vec::new());
        let force_calls = RefCell::new(Vec::new());

        rollback_untracked_pid_with(
            12345,
            |pid| graceful_calls.borrow_mut().push(pid),
            |_pid| false,
            |pid| force_calls.borrow_mut().push(pid),
        );

        assert_eq!(*graceful_calls.borrow(), vec![12345]);
        assert!(
            force_calls.borrow().is_empty(),
            "force-stop should not be called when pid already exited"
        );

        rollback_untracked_pid_with(
            12345,
            |pid| graceful_calls.borrow_mut().push(pid),
            |_pid| true,
            |pid| force_calls.borrow_mut().push(pid),
        );

        assert_eq!(*graceful_calls.borrow(), vec![12345, 12345]);
        assert_eq!(*force_calls.borrow(), vec![12345]);
    }

    #[test]
    fn validate_force_errors_returns_all_remaining_failed_pids() {
        let result = validate_force_errors_with(
            vec![
                force_error(22334, "web (pid 22334): blocked"),
                force_error(33445, "worker (pid 33445): denied"),
            ],
            |_pid| true,
        );
        assert!(result.is_err(), "expected validation failure");
        let message = format!("{:#}", result.expect_err("expected force-stop error"));
        assert!(
            message.contains("web (pid 22334): blocked"),
            "missing first remaining error: {message}"
        );
        assert!(
            message.contains("worker (pid 33445): denied"),
            "missing second remaining error: {message}"
        );
    }
}
