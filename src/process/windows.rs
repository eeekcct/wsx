use crate::state::PidEntry;
use anyhow::{Context, Result, bail};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::Child;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetLastError, HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, OpenJobObjectW,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const TASKKILL_GRACE_TIMEOUT_MS: u64 = 1500;
const TASKKILL_FORCE_TIMEOUT_MS: u64 = 1500;
const TASKKILL_POLL_INTERVAL_MS: u64 = 50;
const JOB_NAME_PREFIX: &str = r"Global\wsx";
const MAX_JOB_NAME_LEN: usize = 200;
const JOB_OBJECT_TERMINATE_ACCESS: u32 = 0x0008;

pub fn apply_spawn_settings(command: &mut Command) {
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

pub fn attach_to_job(instance_id: &str, process_name: &str, child: &Child) -> Result<String> {
    let job_name = build_job_name(instance_id, process_name, child.id());
    let job_name_wide = to_wide_null(&job_name);
    let handle = unsafe { CreateJobObjectW(std::ptr::null(), job_name_wide.as_ptr()) };
    if handle.is_null() {
        return Err(last_os_error("failed to create Windows job object"));
    }
    let job = WinHandle::new(handle);
    set_job_kill_on_close(job.raw())?;

    let child_handle = child.as_raw_handle() as HANDLE;
    let ok = unsafe { AssignProcessToJobObject(job.raw(), child_handle) };
    if ok == 0 {
        bail!(
            "failed to assign process (pid {}) to Windows job `{}`: {}",
            child.id(),
            job_name,
            last_os_error("AssignProcessToJobObject")
        );
    }

    pin_job_handle_in_process(job.raw(), child_handle)?;

    Ok(job_name)
}

pub fn send_graceful(pid: u32) {
    let _ = run_taskkill(
        &["/PID", &pid.to_string(), "/T"],
        Duration::from_millis(TASKKILL_GRACE_TIMEOUT_MS),
    );
}

pub fn force_stop_tree(pid: u32) {
    let _ = run_taskkill(
        &["/PID", &pid.to_string(), "/T", "/F"],
        Duration::from_millis(TASKKILL_FORCE_TIMEOUT_MS),
    );
}

pub fn send_force(entry: &PidEntry) -> Result<()> {
    send_force_with_runner(entry, terminate_job)
}

fn run_taskkill(args: &[&str], timeout: Duration) -> bool {
    run_quiet_command_with_timeout("taskkill", args, timeout)
}

fn send_force_with_runner<F>(entry: &PidEntry, mut terminate_job_fn: F) -> Result<()>
where
    F: FnMut(&str) -> Result<()>,
{
    let Some(job_name) = entry.windows_job_name.as_deref() else {
        bail!(
            "missing windows job tracking for process `{}` (pid {})",
            entry.name,
            entry.pid
        );
    };
    terminate_job_fn(job_name).with_context(|| {
        format!(
            "failed to terminate Windows job `{}` for process `{}` (pid {})",
            job_name, entry.name, entry.pid
        )
    })
}

fn terminate_job(job_name: &str) -> Result<()> {
    let job_name_wide = to_wide_null(job_name);
    let handle = unsafe { OpenJobObjectW(JOB_OBJECT_TERMINATE_ACCESS, 0, job_name_wide.as_ptr()) };
    if handle.is_null() {
        return Err(last_os_error(&format!(
            "failed to open Windows job `{job_name}`"
        )));
    }
    let job = WinHandle::new(handle);

    let ok = unsafe { TerminateJobObject(job.raw(), 1) };
    if ok == 0 {
        return Err(last_os_error(&format!(
            "failed to terminate Windows job `{job_name}`"
        )));
    }

    Ok(())
}

fn set_job_kill_on_close(job: HANDLE) -> Result<()> {
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_os_error(
            "failed to set JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
        ));
    }
    Ok(())
}

fn pin_job_handle_in_process(job: HANDLE, process: HANDLE) -> Result<()> {
    let mut _job_handle_in_target: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            job,
            process,
            &mut _job_handle_in_target,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(last_os_error(
            "failed to duplicate job handle into managed process",
        ));
    }
    Ok(())
}

fn build_job_name(instance_id: &str, process_name: &str, pid: u32) -> String {
    let safe_instance = truncate_ascii(&sanitize_component(instance_id), 64);
    let safe_process = truncate_ascii(&sanitize_component(process_name), 96);
    let prefix = format!("{JOB_NAME_PREFIX}-{safe_instance}-");
    let suffix = format!("-{pid}");
    let max_process_len = MAX_JOB_NAME_LEN.saturating_sub(prefix.len() + suffix.len());
    let process_part = truncate_ascii(&safe_process, max_process_len.max(1));

    format!("{prefix}{process_part}{suffix}")
}

fn sanitize_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() { "_".to_string() } else { out }
}

fn truncate_ascii(input: &str, max_len: usize) -> String {
    input.chars().take(max_len).collect()
}

fn to_wide_null(input: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = input.encode_utf16().collect();
    wide.push(0);
    wide
}

fn last_os_error(action: &str) -> anyhow::Error {
    let code = unsafe { GetLastError() } as i32;
    let error = std::io::Error::from_raw_os_error(code);
    anyhow::anyhow!("{action}: {error}")
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

struct WinHandle(HANDLE);

impl WinHandle {
    fn new(raw: HANDLE) -> Self {
        Self(raw)
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_JOB_NAME_LEN, build_job_name, send_force_with_runner};
    use crate::state::PidEntry;

    fn sample_entry(job_name: Option<&str>) -> PidEntry {
        PidEntry {
            name: "backend".to_string(),
            pid: 1234,
            out_log: "out.log".to_string(),
            err_log: "err.log".to_string(),
            combined_log: "combined.log".to_string(),
            windows_job_name: job_name.map(ToString::to_string),
        }
    }

    #[test]
    fn force_stop_uses_stored_job_name() {
        let entry = sample_entry(Some(r"Global\wsx-demo-backend-1234"));
        let mut called = Vec::new();
        send_force_with_runner(&entry, |job_name| {
            called.push(job_name.to_string());
            Ok(())
        })
        .expect("force stop should succeed");
        assert_eq!(called, vec![r"Global\wsx-demo-backend-1234"]);
    }

    #[test]
    fn force_stop_fails_without_job_name() {
        let entry = sample_entry(None);
        let err = send_force_with_runner(&entry, |_job_name| Ok(()))
            .expect_err("missing job name should fail");
        assert!(
            err.to_string().contains("missing windows job tracking"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn build_job_name_sanitizes_components() {
        let name = build_job_name("demo id", "backend/main", 42);
        assert!(name.starts_with(r"Global\wsx-"));
        assert!(name.ends_with("-42"));
        assert!(!name.contains(' '));
        assert!(!name.contains('/'));
    }

    #[test]
    fn build_job_name_is_bounded() {
        let long_instance = "i".repeat(300);
        let long_process = "p".repeat(300);
        let name = build_job_name(&long_instance, &long_process, 42);
        assert!(name.len() <= MAX_JOB_NAME_LEN);
    }
}
