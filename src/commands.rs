use anyhow::{Context, Result, bail};
use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use uuid::Uuid;

use crate::cli::{Cli, Command};
use crate::config::{Config, ResolvedWorkspace};
use crate::env;
use crate::logs;
use crate::paths;
use crate::process;
use crate::state::{self, CurrentState};

pub fn run(cli: Cli) -> Result<()> {
    match (cli.workspace, cli.command) {
        (Some(workspace), None) => switch_workspace(&workspace),
        (None, Some(Command::Down)) => down_current(None),
        (None, Some(Command::Logs { target, lines })) => logs_current(target, lines),
        (None, Some(Command::Status)) => status_current(),
        (None, None) => bail!("workspace or subcommand is required"),
        (Some(_), Some(_)) => bail!("workspace argument and subcommand cannot be used together"),
    }
}

fn switch_workspace(workspace_name: &str) -> Result<()> {
    paths::ensure_home_layout()?;

    let config = Config::load()?;
    let workspace = config.resolve_workspace(workspace_name)?;

    down_current(Some(&config))?;

    let env_map = env::build_environment(&workspace)?;
    let instance_id = Uuid::new_v4().to_string();

    let pids = process::start_workspace(&workspace, &instance_id, &env_map)?;

    state::save_pids(&pids)?;
    state::save_current(&CurrentState {
        workspace: workspace.name.clone(),
        instance_id,
        started_at: Utc::now(),
    })?;

    println!("switched to workspace `{}`", workspace.name);
    logs::show_logs(&pids, &workspace.logs_default, workspace.logs_lines, true)?;
    cleanup_workspace_instances(
        &workspace.name,
        workspace.logs_keep_instances,
        Some(&pids.instance_id),
    )?;
    Ok(())
}

fn down_current(config: Option<&Config>) -> Result<()> {
    let current = match state::load_current() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("warning: current state is invalid, clearing it: {err:#}");
            state::clear_current()?;
            return Ok(());
        }
    };

    let Some(current) = current else {
        println!("no running workspace");
        return Ok(());
    };

    let pids_file = match state::load_pids(&current.instance_id) {
        Ok(pids) => pids,
        Err(err) => {
            eprintln!(
                "warning: pids file for instance `{}` could not be read: {err:#}",
                current.instance_id
            );
            state::clear_current()?;
            return Ok(());
        }
    };

    let grace_seconds = resolve_grace_seconds(config, &current.workspace);
    process::stop_workspace(&pids_file, grace_seconds)?;
    state::clear_current()?;
    let keep_instances = resolve_keep_instances(config, &current.workspace);
    cleanup_workspace_instances(&current.workspace, keep_instances, None)?;

    println!("stopped workspace `{}`", current.workspace);

    Ok(())
}

fn logs_current(target: Option<String>, lines: Option<usize>) -> Result<()> {
    let current = state::load_current()?.context("no running workspace")?;
    let pids = state::load_pids(&current.instance_id)?;

    let (default_target, default_lines) = resolve_log_defaults(&current.workspace, &pids);

    let resolved_target = target.unwrap_or(default_target);
    let resolved_lines = lines.unwrap_or(default_lines);

    logs::show_logs(&pids, &resolved_target, resolved_lines, true)?;
    Ok(())
}

fn status_current() -> Result<()> {
    let current = match state::load_current() {
        Ok(value) => value,
        Err(err) => {
            println!("Current: invalid ({err:#})");
            return Ok(());
        }
    };

    let Some(current) = current else {
        println!("Current: none");
        return Ok(());
    };

    println!("Current workspace: {}", current.workspace);
    println!("Instance ID: {}", current.instance_id);
    println!("Started at: {}", current.started_at);

    let pids = match state::load_pids(&current.instance_id) {
        Ok(value) => value,
        Err(err) => {
            println!("Processes: unavailable ({err:#})");
            return Ok(());
        }
    };

    for entry in pids.entries {
        let status = if process::is_pid_running(entry.pid) {
            "running"
        } else {
            "stopped"
        };

        println!("- {} (pid {}): {}", entry.name, entry.pid, status);
    }

    Ok(())
}

fn resolve_grace_seconds(config: Option<&Config>, workspace_name: &str) -> u64 {
    if let Some(config) = config {
        if let Ok(workspace) = config.resolve_workspace(workspace_name) {
            return workspace.grace_seconds;
        }
        return config.default_grace_seconds();
    }

    match Config::load() {
        Ok(config) => match config.resolve_workspace(workspace_name) {
            Ok(workspace) => workspace.grace_seconds,
            Err(_) => config.default_grace_seconds(),
        },
        Err(_) => 5,
    }
}

fn resolve_keep_instances(config: Option<&Config>, workspace_name: &str) -> usize {
    if let Some(config) = config {
        if let Ok(workspace) = config.resolve_workspace(workspace_name) {
            return workspace.logs_keep_instances;
        }
        return config.default_log_keep_instances();
    }

    match Config::load() {
        Ok(config) => match config.resolve_workspace(workspace_name) {
            Ok(workspace) => workspace.logs_keep_instances,
            Err(_) => config.default_log_keep_instances(),
        },
        Err(_) => 20,
    }
}

fn resolve_log_defaults(workspace_name: &str, pids: &crate::state::PidsFile) -> (String, usize) {
    let config = match Config::load() {
        Ok(config) => config,
        Err(_) => {
            let fallback_target = pids
                .entries
                .first()
                .map(|entry| entry.name.clone())
                .unwrap_or_else(|| "backend".to_string());
            return (fallback_target, 200);
        }
    };

    let default_lines = config.default_log_lines();

    let workspace: Option<ResolvedWorkspace> = config.resolve_workspace(workspace_name).ok();
    if let Some(workspace) = workspace {
        return (workspace.logs_default, workspace.logs_lines);
    }

    let fallback_target = pids
        .entries
        .first()
        .map(|entry| entry.name.clone())
        .unwrap_or_else(|| config.defaults.logs.default.clone());

    (fallback_target, default_lines)
}

#[derive(Debug)]
struct InstanceDir {
    id: String,
    path: PathBuf,
    modified: SystemTime,
}

fn cleanup_workspace_instances(
    workspace_name: &str,
    keep_instances: usize,
    protected_instance_id: Option<&str>,
) -> Result<()> {
    if keep_instances == 0 {
        return Ok(());
    }

    let instances_root = paths::instances_dir()?;
    if !instances_root.exists() {
        return Ok(());
    }

    let mut candidates = Vec::new();

    for entry in fs::read_dir(&instances_root)
        .with_context(|| format!("failed to read {}", instances_root.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read {}", instances_root.display()))?;
        let entry_type = entry.file_type().with_context(|| {
            format!(
                "failed to determine file type for {}",
                entry.path().display()
            )
        })?;
        if !entry_type.is_dir() {
            continue;
        }

        let id = entry.file_name().to_string_lossy().to_string();
        let pids = match state::load_pids(&id) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if pids.workspace != workspace_name {
            continue;
        }

        let modified = fs::metadata(entry.path())
            .and_then(|meta| meta.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        candidates.push(InstanceDir {
            id,
            path: entry.path(),
            modified,
        });
    }

    candidates.sort_by(|a, b| b.modified.cmp(&a.modified));

    let mut kept = 0usize;
    for instance in candidates {
        if protected_instance_id.is_some_and(|id| id == instance.id) {
            kept += 1;
            continue;
        }

        if kept < keep_instances {
            kept += 1;
            continue;
        }

        if let Err(err) = fs::remove_dir_all(&instance.path) {
            eprintln!(
                "warning: failed to remove old instance `{}`: {err:#}",
                instance.id
            );
        }
    }

    Ok(())
}
