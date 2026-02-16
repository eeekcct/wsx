use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::config::ResolvedWorkspace;

pub fn build_environment(workspace: &ResolvedWorkspace) -> Result<HashMap<String, String>> {
    let mut env_map: HashMap<String, String> = std::env::vars().collect();

    apply_dotenv_files(&workspace.path, &workspace.dotenv, &mut env_map)?;

    if workspace.envrc {
        apply_envrc(&workspace.path, &mut env_map)?;
    }

    Ok(env_map)
}

fn apply_dotenv_files(
    workspace_path: &Path,
    dotenv_files: &[String],
    env_map: &mut HashMap<String, String>,
) -> Result<()> {
    for file in dotenv_files {
        let path = workspace_path.join(file);
        if !path.exists() {
            continue;
        }

        let iter = dotenvy::from_path_iter(&path)
            .with_context(|| format!("failed to parse dotenv file {}", path.display()))?;

        for entry in iter {
            let (key, value) =
                entry.with_context(|| format!("invalid dotenv entry in {}", path.display()))?;
            env_map.insert(key, value);
        }
    }

    Ok(())
}

fn apply_envrc(workspace_path: &Path, env_map: &mut HashMap<String, String>) -> Result<()> {
    let envrc = workspace_path.join(".envrc");
    if !envrc.exists() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        let output = Command::new("sh")
            .arg("-c")
            .arg("set -a; . ./.envrc; env")
            .current_dir(workspace_path)
            .env_clear()
            .envs(env_map.iter())
            .output()
            .context("failed to execute .envrc via sh")?;

        if !output.status.success() {
            bail!(
                ".envrc execution failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        merge_env_output(&output.stdout, env_map);
    }

    #[cfg(windows)]
    {
        let output = Command::new("bash")
            .arg("-c")
            .arg("set -a; source ./.envrc; env")
            .current_dir(workspace_path)
            .env_clear()
            .envs(env_map.iter())
            .output();

        match output {
            Ok(output) => {
                if !output.status.success() {
                    bail!(
                        ".envrc execution failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }
                merge_env_output(&output.stdout, env_map);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!(
                    "warning: bash was not found on this machine; .envrc was skipped for this run"
                );
            }
            Err(err) => {
                return Err(err).context("failed to execute .envrc via bash");
            }
        }
    }

    Ok(())
}

fn merge_env_output(raw_output: &[u8], env_map: &mut HashMap<String, String>) {
    let output = String::from_utf8_lossy(raw_output);
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if !key.is_empty() {
                env_map.insert(key.to_string(), value.to_string());
            }
        }
    }
}
