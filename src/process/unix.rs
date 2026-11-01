use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

/// Probe group existence without delivering a signal or enumerating processes.
/// This is not a live-member count: on Linux, unreaped zombies also keep
/// a group detectable. Other Unix kernels may report zombie-only groups differently.
pub fn is_process_group_running(pid: u32) -> bool {
    is_process_group_running_with(pid, |group| kill(group, None))
}

fn is_process_group_running_with<F>(pid: u32, mut probe: F) -> bool
where
    F: FnMut(Pid) -> Result<(), Errno>,
{
    let Some(group) = process_group_pid(pid) else {
        return false;
    };
    match probe(group) {
        Ok(()) | Err(Errno::EPERM) => true,
        Err(Errno::ESRCH) => false,
        Err(err) => {
            traxer::warn!("could not check process group {pid}: {err}; treating it as running");
            true
        }
    }
}

/// Reap only the saved PID if it is our exited direct child. Never block or
/// consume another child's status. A separate wsx invocation gets ECHILD.
pub fn reap_tracked_child(pid: u32) -> bool {
    reap_tracked_child_with(pid, |child| waitpid(child, Some(WaitPidFlag::WNOHANG)))
}

fn reap_tracked_child_with<F>(pid: u32, mut reap: F) -> bool
where
    F: FnMut(Pid) -> Result<WaitStatus, Errno>,
{
    let Some(child) = positive_group_pid(pid) else {
        return true;
    };
    match reap(child) {
        Ok(_) | Err(Errno::ECHILD) => true,
        Err(err) => {
            traxer::warn!("could not reap tracked child {pid}: {err}; retaining it this poll");
            false
        }
    }
}

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
    Some(Pid::from_raw(-positive_group_pid(pid)?.as_raw()))
}

fn positive_group_pid(pid: u32) -> Option<Pid> {
    let raw_pid = i32::try_from(pid).ok()?;
    // 0 and -1 have special kill semantics, not a tracked child's group.
    (raw_pid > 1).then(|| Pid::from_raw(raw_pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reap_is_limited_to_the_positive_saved_pid() {
        assert!(reap_tracked_child_with(42, |pid| {
            assert_eq!(pid, Pid::from_raw(42));
            Ok(WaitStatus::Exited(pid, 0))
        }));
        assert!(reap_tracked_child_with(42, |_| Ok(WaitStatus::StillAlive)));
        assert!(reap_tracked_child_with(42, |_| Err(Errno::ECHILD)));
        assert!(!reap_tracked_child_with(42, |_| Err(Errno::EINTR)));
        assert!(!reap_tracked_child_with(42, |_| Err(Errno::EIO)));
        for pid in [0, 1, u32::MAX] {
            assert!(reap_tracked_child_with(pid, |_| panic!(
                "invalid saved PID"
            )));
        }
    }

    #[test]
    fn probes_the_group_once_without_requiring_its_leader() {
        let mut calls = 0;
        assert!(is_process_group_running_with(42, |group| {
            calls += 1;
            assert_eq!(group, Pid::from_raw(-42));
            Ok(())
        }));
        assert_eq!(calls, 1);
    }

    #[test]
    fn success_including_zombie_only_existence_is_running() {
        // A successful probe does not prove a live member exists (e.g. Linux zombies).
        assert!(is_process_group_running_with(42, |_| Ok(())));
    }

    #[test]
    fn permission_denied_is_running() {
        assert!(is_process_group_running_with(42, |_| Err(Errno::EPERM)));
    }

    #[test]
    fn missing_group_is_stopped() {
        assert!(!is_process_group_running_with(42, |_| Err(Errno::ESRCH)));
    }

    #[test]
    fn unexpected_probe_error_is_conservatively_running() {
        assert!(is_process_group_running_with(42, |_| Err(Errno::EIO)));
    }

    #[test]
    fn rejects_special_or_unrepresentable_group_ids_without_probing() {
        for pid in [0, 1, i32::MAX as u32 + 1, u32::MAX] {
            assert!(process_group_pid(pid).is_none());
            assert!(!is_process_group_running_with(pid, |_| {
                panic!("invalid group IDs must never reach kill")
            }));
        }
        assert_eq!(process_group_pid(42), Some(Pid::from_raw(-42)));
        assert_eq!(
            process_group_pid(i32::MAX as u32),
            Some(Pid::from_raw(-i32::MAX)),
        );
    }
}
