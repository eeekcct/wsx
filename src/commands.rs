use anyhow::{Context, Result, bail};
use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::SystemTime;
use uuid::Uuid;

use crate::cli::{Cli, Command};
use crate::config::{Config, ResolvedWorkspace};
use crate::env;
use crate::logs;
use crate::paths;
use crate::process;
use crate::state::{self, CurrentState, CurrentStatus};

pub fn run(cli: Cli) -> Result<()> {
    match (cli.workspace, cli.command) {
        (Some(workspace), None) => switch_workspace(&workspace),
        (None, Some(Command::List)) => list_workspaces(),
        (None, Some(Command::Up)) => up_current(),
        (None, Some(Command::Down)) => down_current(None),
        (
            None,
            Some(Command::Logs {
                target,
                lines,
                no_follow,
            }),
        ) => logs_current(target, lines, !no_follow),
        (None, Some(Command::Exec { cmd })) => exec_current(cmd),
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

    start_workspace_instance(&workspace, "switched to")
}

fn up_current() -> Result<()> {
    paths::ensure_home_layout()?;
    let current = load_current_reconciled()?.context("no current workspace")?;

    if current.status == CurrentStatus::Running {
        println!("workspace `{}` is already running", current.workspace);
        return Ok(());
    }

    let config = Config::load()?;
    let workspace = config.resolve_workspace(&current.workspace)?;
    start_workspace_instance(&workspace, "started")
}

fn start_workspace_instance(workspace: &ResolvedWorkspace, action: &str) -> Result<()> {
    let env_map = env::build_environment(workspace)?;
    let instance_id = Uuid::new_v4().to_string();

    let pids = process::start_workspace(workspace, &instance_id, &env_map)?;

    state::save_pids(&pids)?;
    state::save_current(&CurrentState {
        workspace: workspace.name.clone(),
        instance_id,
        started_at: Utc::now(),
        status: CurrentStatus::Running,
    })?;

    println!("{action} workspace `{}`", workspace.name);
    logs::show_logs(&pids, &workspace.logs_default, workspace.logs_lines, true)?;
    cleanup_workspace_instances(
        &workspace.name,
        workspace.logs_keep_instances,
        Some(&pids.instance_id),
    )?;

    Ok(())
}

fn list_workspaces() -> Result<()> {
    let config = Config::load()?;
    let current_workspace = match state::load_current() {
        Ok(Some(current)) => Some(current.workspace),
        Ok(None) => None,
        Err(err) => {
            eprintln!("warning: current state is invalid, ignoring it: {err:#}");
            None
        }
    };

    let workspace_names: Vec<String> = config.workspaces.keys().cloned().collect();
    let lines = render_workspace_list(workspace_names, current_workspace.as_deref());
    for line in lines {
        println!("{line}");
    }

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

    let Some(mut current) = current else {
        println!("no current workspace");
        return Ok(());
    };

    if current.status == CurrentStatus::Stopped {
        println!("workspace `{}` is already stopped", current.workspace);
        return Ok(());
    }

    let pids_file = state::load_pids(&current.instance_id).with_context(|| {
        format!(
            "pids file for instance `{}` could not be read",
            current.instance_id
        )
    })?;

    let grace_seconds = resolve_grace_seconds(config, &current.workspace);
    process::stop_workspace(&pids_file, grace_seconds)?;
    current.status = CurrentStatus::Stopped;
    state::save_current(&current)?;
    let keep_instances = resolve_keep_instances(config, &current.workspace);
    cleanup_workspace_instances(
        &current.workspace,
        keep_instances,
        Some(&current.instance_id),
    )?;

    println!("stopped workspace `{}`", current.workspace);

    Ok(())
}

fn logs_current(target: Option<String>, lines: Option<usize>, follow: bool) -> Result<()> {
    let current = load_current_reconciled()?.context("no current workspace")?;
    let pids = state::load_pids(&current.instance_id)?;

    let (default_target, default_lines) = resolve_log_defaults(&current.workspace, &pids);

    let resolved_target = target.unwrap_or(default_target);
    let resolved_lines = lines.unwrap_or(default_lines);

    logs::show_logs(&pids, &resolved_target, resolved_lines, follow)?;
    Ok(())
}

fn exec_current(cmd: Vec<String>) -> Result<()> {
    let current = load_current_reconciled()?.context("no current workspace")?;

    let config = Config::load()?;
    let workspace = config.resolve_workspace(&current.workspace)?;
    let env_map = env::build_environment(&workspace)?;

    let mut command = ProcessCommand::new(&cmd[0]);
    command
        .args(&cmd[1..])
        .current_dir(&workspace.path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env_clear()
        .envs(env_map.iter());

    let status = command
        .status()
        .with_context(|| format!("failed to execute command {:?}", cmd))?;

    match status.code() {
        Some(0) => Ok(()),
        Some(code) => std::process::exit(code),
        None => bail!("command was terminated by signal"),
    }
}

fn print_current_overview(current: &CurrentState) {
    println!("Current workspace: {}", current.workspace);
    println!("State: {}", current.status.as_str());
    println!("Instance ID: {}", current.instance_id);
    println!("Started at: {}", current.started_at);
}

fn print_process_overview(instance_id: &str) -> Result<()> {
    let pids = match state::load_pids(instance_id) {
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

fn status_current() -> Result<()> {
    let current = match load_current_reconciled() {
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

    print_current_overview(&current);
    print_process_overview(&current.instance_id)
}

fn load_current_reconciled() -> Result<Option<CurrentState>> {
    let Some(mut current) = state::load_current()? else {
        return Ok(None);
    };

    if current.status != CurrentStatus::Running {
        return Ok(Some(current));
    }

    let pids = match state::load_pids(&current.instance_id) {
        Ok(pids) => pids,
        Err(_) => return Ok(Some(current)),
    };

    let has_running_pid = pids
        .entries
        .iter()
        .any(|entry| process::is_pid_running(entry.pid));
    if !has_running_pid {
        current.status = CurrentStatus::Stopped;
        state::save_current(&current)?;
    }

    Ok(Some(current))
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

fn render_workspace_list(
    mut workspace_names: Vec<String>,
    current_workspace: Option<&str>,
) -> Vec<String> {
    workspace_names.sort();
    workspace_names
        .into_iter()
        .map(|workspace_name| {
            if current_workspace.is_some_and(|current| current == workspace_name) {
                format!("* {workspace_name}")
            } else {
                format!("  {workspace_name}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::render_workspace_list;

    #[test]
    fn workspace_list_is_sorted_and_marks_current() {
        let lines = render_workspace_list(
            vec!["zeta".to_string(), "alpha".to_string(), "beta".to_string()],
            Some("beta"),
        );

        assert_eq!(lines, vec!["  alpha", "* beta", "  zeta"]);
    }

    #[test]
    fn workspace_list_without_current_marks_none() {
        let lines = render_workspace_list(vec!["b".to_string(), "a".to_string()], None);

        assert_eq!(lines, vec!["  a", "  b"]);
    }
}
