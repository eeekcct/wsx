use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;

use crate::paths;

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
    pub instance_id: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PidsFile {
    pub workspace: String,
    pub instance_id: String,
    pub entries: Vec<PidEntry>,
}

pub fn load_current() -> Result<Option<CurrentState>> {
    let path = paths::current_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let state: CurrentState = serde_json::from_str(&raw)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;

    Ok(Some(state))
}

pub fn save_current(state: &CurrentState) -> Result<()> {
    paths::ensure_home_layout()?;
    let path = paths::current_path()?;

    let raw = serde_json::to_string_pretty(state)?;
    fs::write(&path, raw).with_context(|| format!("failed to write {}", path.display()))?;

    Ok(())
}

pub fn clear_current() -> Result<()> {
    let path = paths::current_path()?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

pub fn save_pids(pids: &PidsFile) -> Result<()> {
    let instance_dir = paths::instance_dir(&pids.instance_id)?;
    fs::create_dir_all(&instance_dir)
        .with_context(|| format!("failed to create {}", instance_dir.display()))?;

    let path = paths::pids_path(&pids.instance_id)?;
    let raw = serde_json::to_string_pretty(pids)?;
    fs::write(&path, raw).with_context(|| format!("failed to write {}", path.display()))?;

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
    }
}
