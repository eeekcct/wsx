use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::paths;

/// One exclusive OS lock for the entire state root, not an individual workspace.
/// Keep the file in place: unlinking it would let another process lock a different
/// inode. Dropping this guard (or exiting) releases the lock. Rust opens the file
/// without descriptor/handle inheritance, so launched services cannot retain it.
pub struct LifecycleLock {
    _file: File,
}

pub fn acquire_lifecycle_lock() -> Result<LifecycleLock> {
    paths::ensure_home_layout()?;
    lock_at(&paths::wsx_home()?.join("lifecycle.lock"))
}

fn lock_at(path: &Path) -> Result<LifecycleLock> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("failed to open lifecycle lock {}", path.display()))?;
    file.lock()
        .with_context(|| format!("failed to acquire lifecycle lock {}", path.display()))?;
    Ok(LifecycleLock { _file: file })
}

// Write beside the destination so rename stays on the same filesystem. Never
// remove the destination first: readers see either the old or the complete new
// document, and a failed write/rename leaves the previous state intact.
fn write_atomic(path: &Path, raw: &str) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| {
            format!(
                "failed to create temporary state file {}",
                temporary.display()
            )
        })?;
    let temporary_path = &temporary;
    let result = (move || -> std::io::Result<()> {
        file.write_all(raw.as_bytes())?;
        file.sync_all()?;
        drop(file);
        // std::fs::rename replaces an existing file on Unix and Windows.
        fs::rename(temporary_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("failed to write {} atomically", path.display()))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CurrentStatus {
    Running,
    Stopped,
}

impl CurrentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

fn default_current_status() -> CurrentStatus {
    CurrentStatus::Running
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentState {
    pub workspace: String,
    #[serde(default)]
    pub workspace_path: Option<PathBuf>,
    #[serde(default)]
    pub instance_id: Option<String>,
    pub started_at: DateTime<Utc>,
    #[serde(default = "default_current_status")]
    pub status: CurrentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PidEntry {
    pub name: String,
    pub pid: u32,
    pub out_log: String,
    pub err_log: String,
    pub combined_log: String,
    pub windows_job_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PidsFile {
    pub workspace: String,
    pub instance_id: String,
    pub entries: Vec<PidEntry>,
}

pub fn load_current() -> Result<Option<CurrentState>> {
    let path = paths::current_path()?;
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let state: CurrentState = serde_json::from_str(&raw)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;

    Ok(Some(state))
}

pub fn save_current(state: &CurrentState) -> Result<()> {
    paths::ensure_home_layout()?;
    let path = paths::current_path()?;

    let raw = serde_json::to_string_pretty(state)?;
    write_atomic(&path, &raw)?;

    Ok(())
}

pub fn save_pids(pids: &PidsFile) -> Result<()> {
    let instance_dir = paths::instance_dir(&pids.instance_id)?;
    fs::create_dir_all(&instance_dir)
        .with_context(|| format!("failed to create {}", instance_dir.display()))?;

    let path = paths::pids_path(&pids.instance_id)?;
    let raw = serde_json::to_string_pretty(pids)?;
    write_atomic(&path, &raw)?;

    Ok(())
}

pub fn load_pids(instance_id: &str) -> Result<PidsFile> {
    let path = paths::pids_path(instance_id)?;

    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let pids: PidsFile = serde_json::from_str(&raw)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;

    Ok(pids)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("wsx-state-test-{}", Uuid::new_v4()));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn lifecycle_lock_is_exclusive_and_released_on_drop() {
        let dir = TestDir::new();
        let path = dir.0.join("lifecycle.lock");
        let guard = lock_at(&path).expect("acquire lock");
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(guard);
        contender.try_lock().expect("released lock");
    }

    #[test]
    fn lifecycle_locks_for_different_roots_are_independent() {
        let first = TestDir::new();
        let second = TestDir::new();
        let _first = lock_at(&first.0.join("lifecycle.lock")).unwrap();
        let _second = lock_at(&second.0.join("lifecycle.lock")).unwrap();
    }

    #[test]
    fn atomic_write_replaces_existing_file_without_temporary_files() {
        let dir = TestDir::new();
        let path = dir.0.join("current.json");
        write_atomic(&path, "old").unwrap();
        write_atomic(&path, "new document").unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), "new document");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn atomic_write_failure_preserves_destination_and_cleans_temporary_file() {
        let dir = TestDir::new();
        let path = dir.0.join("current.json");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("preserved"), "old").unwrap();
        assert!(write_atomic(&path, "new").is_err());
        assert_eq!(fs::read_to_string(path.join("preserved")).unwrap(), "old");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn pids_roundtrip_serialization() {
        let file = PidsFile {
            workspace: "deva".to_string(),
            instance_id: "inst".to_string(),
            entries: vec![PidEntry {
                name: "backend".to_string(),
                pid: 1,
                out_log: "o".to_string(),
                err_log: "e".to_string(),
                combined_log: "c".to_string(),
                windows_job_name: None,
            }],
        };

        let raw = serde_json::to_string(&file).expect("serialize");
        let decoded: PidsFile = serde_json::from_str(&raw).expect("deserialize");
        assert_eq!(decoded.entries[0].name, "backend");
    }

    #[test]
    fn current_status_defaults_to_running_for_legacy_json() {
        let raw =
            r#"{"workspace":"deva","instance_id":"inst","started_at":"2025-01-01T00:00:00Z"}"#;
        let current: CurrentState = serde_json::from_str(raw).expect("deserialize current");
        assert_eq!(current.status, CurrentStatus::Running);
        assert_eq!(current.instance_id.as_deref(), Some("inst"));
        assert_eq!(current.workspace_path, None);
    }

    #[test]
    fn current_path_roundtrips_and_remains_optional() {
        let current = CurrentState {
            workspace: "demo".to_string(),
            workspace_path: Some(std::env::current_dir().expect("current directory")),
            instance_id: None,
            started_at: Utc::now(),
            status: CurrentStatus::Stopped,
        };
        let raw = serde_json::to_string(&current).expect("serialize current state");
        let decoded: CurrentState = serde_json::from_str(&raw).expect("parse current state");
        assert_eq!(decoded.workspace_path, current.workspace_path);
    }

    #[test]
    fn current_instance_id_defaults_to_none_when_missing() {
        let raw = r#"{"workspace":"deva","started_at":"2025-01-01T00:00:00Z","status":"stopped"}"#;
        let current: CurrentState = serde_json::from_str(raw).expect("deserialize current");
        assert_eq!(current.instance_id, None);
    }
}
