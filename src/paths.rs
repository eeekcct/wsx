use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::PathBuf;

pub fn wsx_home() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("failed to resolve home directory"))?;
    Ok(home.join(".config").join("wsx"))
}

pub fn config_path() -> Result<PathBuf> {
    Ok(wsx_home()?.join("config.yaml"))
}

pub fn current_path() -> Result<PathBuf> {
    Ok(wsx_home()?.join("current.json"))
}

pub fn instances_dir() -> Result<PathBuf> {
    Ok(wsx_home()?.join("instances"))
}

pub fn instance_dir(instance_id: &str) -> Result<PathBuf> {
    Ok(instances_dir()?.join(instance_id))
}

pub fn logs_dir(instance_id: &str) -> Result<PathBuf> {
    Ok(instance_dir(instance_id)?.join("logs"))
}

pub fn pids_path(instance_id: &str) -> Result<PathBuf> {
    Ok(instance_dir(instance_id)?.join("pids.json"))
}

pub fn ensure_home_layout() -> Result<()> {
    let home = wsx_home()?;
    let instances = instances_dir()?;

    fs::create_dir_all(&home).with_context(|| format!("failed to create {}", home.display()))?;
    fs::create_dir_all(&instances)
        .with_context(|| format!("failed to create {}", instances.display()))?;

    Ok(())
}
