use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, getpgid};
use sysinfo::{ProcessStatus, System};

pub fn is_process_group_running(pid: u32) -> bool {
    let Some(group) = positive_group_pid(pid) else {
        return false;
    };
    let system = System::new_all();
    let processes = system
        .processes()
        .iter()
        .map(|(pid, process)| (pid.as_u32(), process.status()));

    match snapshot_has_live_group_member(group, processes, |pid| {
        let raw_pid = i32::try_from(pid).map_err(|_| Errno::EINVAL)?;
        getpgid(Some(Pid::from_raw(raw_pid)))
    }) {
        Ok(running) => running,
        Err(err) => {
            // A lookup may be denied for an unrelated process. Probe only our
            // existing group instead of treating every such process as a member.
            // Signal 0 checks existence/permission without delivering a signal.
            traxer::warn!(
                "could not inspect process groups ({err}); checking group {pid} existence"
            );
            match kill(Pid::from_raw(-group.as_raw()), None) {
                Ok(()) | Err(Errno::EPERM) => true,
                Err(Errno::ESRCH) => false,
                Err(err) => {
                    traxer::warn!(
                        "could not check process group {pid}: {err}; treating it as running"
                    );
                    true
                }
            }
        }
    }
}

fn snapshot_has_live_group_member<I, F>(
    group: Pid,
    processes: I,
    mut process_group: F,
) -> Result<bool, Errno>
where
    I: IntoIterator<Item = (u32, ProcessStatus)>,
    F: FnMut(u32) -> Result<Pid, Errno>,
{
    let mut lookup_error = None;
    for (pid, status) in processes {
        if matches!(status, ProcessStatus::Zombie | ProcessStatus::Dead) {
            continue;
        }
        match process_group(pid) {
            Ok(actual_group) if actual_group == group => return Ok(true),
            Ok(_) | Err(Errno::ESRCH) => {}
            Err(err) => lookup_error = Some(err),
        }
    }
    match lookup_error {
        Some(err) => Err(err),
        None => Ok(false),
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
    fn finds_live_child_after_group_leader_exits() {
        let group = Pid::from_raw(42);
        assert_eq!(
            snapshot_has_live_group_member(
                group,
                [(42, ProcessStatus::Zombie), (43, ProcessStatus::Sleep)],
                |pid| {
                    assert_eq!(pid, 43, "zombie leader must be skipped");
                    Ok(group)
                },
            ),
            Ok(true),
        );
    }

    #[test]
    fn ignores_dead_members_unrelated_groups_and_disappeared_processes() {
        assert_eq!(
            snapshot_has_live_group_member(
                Pid::from_raw(42),
                [
                    (42, ProcessStatus::Dead),
                    (43, ProcessStatus::Zombie),
                    (44, ProcessStatus::Sleep),
                    (45, ProcessStatus::Sleep),
                ],
                |pid| match pid {
                    44 => Ok(Pid::from_raw(99)),
                    45 => Err(Errno::ESRCH),
                    _ => panic!("dead processes must not be queried"),
                },
            ),
            Ok(false),
        );
    }

    #[test]
    fn denied_lookup_is_not_treated_as_a_gone_process() {
        assert_eq!(
            snapshot_has_live_group_member(Pid::from_raw(42), [(43, ProcessStatus::Sleep)], |_| {
                Err(Errno::EPERM)
            },),
            Err(Errno::EPERM),
        );
    }

    #[test]
    fn rejects_special_or_unrepresentable_group_ids() {
        for pid in [0, 1, u32::MAX] {
            assert!(process_group_pid(pid).is_none());
            assert!(!is_process_group_running(pid));
        }
        assert_eq!(process_group_pid(42), Some(Pid::from_raw(-42)));
    }
}
