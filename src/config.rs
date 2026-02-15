use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::paths;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub defaults: Defaults,
    pub workspaces: HashMap<String, WorkspaceConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Defaults {
    pub stop: StopDefaults,
    pub env: EnvDefaults,
    pub logs: LogsDefaults,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            stop: StopDefaults::default(),
            env: EnvDefaults::default(),
            logs: LogsDefaults::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StopDefaults {
    pub grace_seconds: u64,
}

impl Default for StopDefaults {
    fn default() -> Self {
        Self { grace_seconds: 5 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EnvDefaults {
    pub dotenv: Vec<String>,
    pub envrc: bool,
}

impl Default for EnvDefaults {
    fn default() -> Self {
        Self {
            dotenv: vec![".env".to_string()],
            envrc: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogsDefaults {
    pub lines: usize,
    pub default: String,
    pub keep_instances: usize,
}

impl Default for LogsDefaults {
    fn default() -> Self {
        Self {
            lines: 200,
            default: String::new(),
            keep_instances: 20,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkspaceConfig {
    pub path: String,
    #[serde(default)]
    pub stop: WorkspaceStop,
    #[serde(default)]
    pub env: WorkspaceEnv,
    #[serde(default)]
    pub logs: WorkspaceLogs,
    #[serde(default)]
    pub processes: Vec<ProcessConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct WorkspaceStop {
    pub grace_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct WorkspaceEnv {
    pub dotenv: Option<Vec<String>>,
    pub envrc: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct WorkspaceLogs {
    pub lines: Option<usize>,
    pub default: Option<String>,
    pub keep_instances: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProcessConfig {
    pub name: Option<String>,
    pub cmd: Vec<String>,
    #[serde(default)]
    pub default_log: bool,
    #[serde(default)]
    pub default_stream: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedWorkspace {
    pub name: String,
    pub path: PathBuf,
    pub grace_seconds: u64,
    pub dotenv: Vec<String>,
    pub envrc: bool,
    pub logs_lines: usize,
    pub logs_default: String,
    pub logs_keep_instances: usize,
    pub processes: Vec<ResolvedProcess>,
}

#[derive(Debug, Clone)]
pub struct ResolvedProcess {
    pub name: String,
    pub cmd: Vec<String>,
    pub default_log: bool,
    pub default_stream: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = paths::config_path()?;
        if !path.exists() {
            bail!("config file not found: {}", path.display());
        }

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        let config: Self = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid YAML in {}", path.display()))?;

        if config.workspaces.is_empty() {
            bail!("workspaces is empty in {}", path.display());
        }

        Ok(config)
    }

    pub fn default_grace_seconds(&self) -> u64 {
        self.defaults.stop.grace_seconds
    }

    pub fn default_log_lines(&self) -> usize {
        self.defaults.logs.lines
    }

    pub fn default_log_keep_instances(&self) -> usize {
        self.defaults.logs.keep_instances
    }

    pub fn resolve_workspace(&self, workspace_name: &str) -> Result<ResolvedWorkspace> {
        let workspace = self
            .workspaces
            .get(workspace_name)
            .with_context(|| format!("workspace `{workspace_name}` is not defined"))?;

        if workspace.processes.is_empty() {
            bail!("workspace `{workspace_name}` has no processes");
        }

        let path = PathBuf::from(&workspace.path);
        if !path.exists() {
            bail!("workspace path does not exist: {}", path.display());
        }
        if !path.is_dir() {
            bail!("workspace path is not a directory: {}", path.display());
        }

        let grace_seconds = workspace
            .stop
            .grace_seconds
            .unwrap_or(self.defaults.stop.grace_seconds);

        let dotenv = workspace
            .env
            .dotenv
            .clone()
            .unwrap_or_else(|| self.defaults.env.dotenv.clone());

        let envrc = workspace.env.envrc.unwrap_or(self.defaults.env.envrc);

        let logs_lines = workspace.logs.lines.unwrap_or(self.defaults.logs.lines);
        let logs_keep_instances = workspace
            .logs
            .keep_instances
            .unwrap_or(self.defaults.logs.keep_instances);

        let processes = resolve_processes(&workspace.processes)?;
        let process_names: HashSet<&str> = processes.iter().map(|p| p.name.as_str()).collect();

        let mut logs_default = workspace.logs.default.clone().unwrap_or_default();
        if logs_default.trim().is_empty() {
            logs_default = self.defaults.logs.default.clone();
        }
        if logs_default.trim().is_empty() {
            logs_default = default_target_from_processes(&processes);
        }

        validate_log_target(&logs_default, &process_names)?;

        Ok(ResolvedWorkspace {
            name: workspace_name.to_string(),
            path,
            grace_seconds,
            dotenv,
            envrc,
            logs_lines,
            logs_default,
            logs_keep_instances,
            processes,
        })
    }
}

fn resolve_processes(items: &[ProcessConfig]) -> Result<Vec<ResolvedProcess>> {
    let mut out = Vec::with_capacity(items.len());
    let mut name_counter: HashMap<String, usize> = HashMap::new();

    for process in items {
        if process.cmd.is_empty() {
            bail!("process cmd must not be empty");
        }

        let base_name = process
            .name
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| default_name_from_cmd(&process.cmd[0]));

        if base_name.trim().is_empty() {
            bail!("process name could not be resolved from cmd[0]");
        }

        let count = name_counter.entry(base_name.clone()).or_insert(0);
        *count += 1;
        let resolved_name = if *count == 1 {
            base_name
        } else {
            format!("{}-{}", base_name, *count)
        };

        out.push(ResolvedProcess {
            name: resolved_name,
            cmd: process.cmd.clone(),
            default_log: process.default_log,
            default_stream: resolve_default_stream(process.default_stream.clone())?,
        });
    }

    Ok(out)
}

fn resolve_default_stream(stream: Option<String>) -> Result<Option<String>> {
    match stream {
        None => Ok(None),
        Some(value) => {
            let normalized = value.trim().to_lowercase();
            if normalized.is_empty() || normalized == "combined" {
                return Ok(None);
            }
            if normalized == "out" || normalized == "err" {
                return Ok(Some(normalized));
            }
            bail!("invalid default_stream `{value}`: expected combined, out, or err");
        }
    }
}

fn default_target_from_processes(processes: &[ResolvedProcess]) -> String {
    if let Some(process) = processes.iter().find(|process| process.default_log) {
        if let Some(stream) = &process.default_stream {
            return format!("{}:{stream}", process.name);
        }
        return process.name.clone();
    }

    if let Some(process) = processes.first() {
        if let Some(stream) = &process.default_stream {
            return format!("{}:{stream}", process.name);
        }
        return process.name.clone();
    }

    "backend".to_string()
}

fn default_name_from_cmd(cmd0: &str) -> String {
    let path = Path::new(cmd0);
    match path.file_name().and_then(|name| name.to_str()) {
        Some(value) if !value.trim().is_empty() => value.to_string(),
        _ => cmd0.to_string(),
    }
}

fn validate_log_target(target: &str, process_names: &HashSet<&str>) -> Result<()> {
    if target.trim().is_empty() {
        bail!("logs target is empty");
    }

    let (process_name, stream) = match target.split_once(':') {
        Some((name, stream)) => (name.trim(), Some(stream.trim())),
        None => (target.trim(), None),
    };

    if process_name.is_empty() {
        bail!("invalid logs target `{target}`: process name is empty");
    }

    if let Some(stream) = stream {
        if stream != "out" && stream != "err" {
            bail!("invalid logs target `{target}`: stream must be out or err");
        }
    }

    if !process_names.contains(process_name) {
        bail!("invalid logs target `{target}`: unknown process `{process_name}`");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_process_names_with_suffix() {
        let items = vec![
            ProcessConfig {
                name: None,
                cmd: vec!["npm".into(), "run".into(), "dev".into()],
                default_log: false,
                default_stream: None,
            },
            ProcessConfig {
                name: Some("npm".into()),
                cmd: vec!["node".into(), "server.js".into()],
                default_log: false,
                default_stream: None,
            },
        ];

        let resolved = resolve_processes(&items).expect("resolve");
        assert_eq!(resolved[0].name, "npm");
        assert_eq!(resolved[1].name, "npm-2");
    }

    #[test]
    fn validates_stream_target() {
        let mut names = HashSet::new();
        names.insert("backend");

        assert!(validate_log_target("backend", &names).is_ok());
        assert!(validate_log_target("backend:out", &names).is_ok());
        assert!(validate_log_target("backend:err", &names).is_ok());
        assert!(validate_log_target("backend:foo", &names).is_err());
    }

    #[test]
    fn picks_default_target_from_process_settings() {
        let processes = vec![
            ResolvedProcess {
                name: "frontend".to_string(),
                cmd: vec!["npm".to_string()],
                default_log: false,
                default_stream: None,
            },
            ResolvedProcess {
                name: "backend".to_string(),
                cmd: vec!["go".to_string()],
                default_log: true,
                default_stream: Some("err".to_string()),
            },
        ];

        assert_eq!(default_target_from_processes(&processes), "backend:err");
    }

    #[test]
    fn picks_first_process_when_default_not_set() {
        let processes = vec![
            ResolvedProcess {
                name: "frontend".to_string(),
                cmd: vec!["npm".to_string()],
                default_log: false,
                default_stream: None,
            },
            ResolvedProcess {
                name: "backend".to_string(),
                cmd: vec!["go".to_string()],
                default_log: false,
                default_stream: None,
            },
        ];

        assert_eq!(default_target_from_processes(&processes), "frontend");
    }
}
