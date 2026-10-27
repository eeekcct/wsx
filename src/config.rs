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
#[derive(Default)]
pub struct Defaults {
    pub stop: StopDefaults,
    pub env: EnvDefaults,
    pub logs: LogsDefaults,
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

        let config: Self = serde_norway::from_str(&raw)
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
    let mut used_names = HashSet::new();

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
        let resolved_name = loop {
            *count += 1;
            let candidate = if *count == 1 {
                base_name.clone()
            } else {
                format!("{}-{}", base_name, *count)
            };
            if used_names.insert(candidate.clone()) {
                break candidate;
            }
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

    if let Some(stream) = stream
        && stream != "out"
        && stream != "err"
    {
        bail!("invalid logs target `{target}`: stream must be out or err");
    }

    if !process_names.contains(process_name) {
        bail!("invalid logs target `{target}`: unknown process `{process_name}`");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_yaml(raw: &str) -> Config {
        serde_norway::from_str(raw).expect("valid config YAML")
    }

    #[test]
    fn yaml_empty_workspace_map_is_left_for_load_validation() {
        // Config::load rejects an empty workspace map after deserialization.
        for raw in ["", "{}", "workspaces: {}"] {
            let config = parse_yaml(raw);
            assert!(config.workspaces.is_empty());
            assert_eq!(config.defaults.stop.grace_seconds, 5);
        }
    }

    #[test]
    fn yaml_documented_examples_parse() {
        let docs = include_str!("../docs/CONFIG.md").replace("\r\n", "\n");
        let examples: Vec<_> = docs
            .split("```yaml\n")
            .skip(1)
            .map(|block| block.split("```").next().unwrap())
            .filter(|block| block.contains("workspaces:"))
            .collect();
        assert_eq!(examples.len(), 2);
        for example in examples {
            let config = parse_yaml(example);
            assert_eq!(config.defaults.stop.grace_seconds, 5);
            assert_eq!(config.defaults.env.dotenv, [".env"]);
            assert!(!config.defaults.env.envrc);
            assert_eq!(config.defaults.logs.lines, 200);
            assert_eq!(config.defaults.logs.default, "");
            assert_eq!(config.defaults.logs.keep_instances, 20);
            let workspace = &config.workspaces["deva"];
            assert_eq!(workspace.processes[0].name.as_deref(), Some("backend"));
            assert_eq!(workspace.processes[0].cmd, ["go", "run", "./cmd/server"]);
        }
    }

    #[test]
    fn yaml_omitted_fields_keep_defaults() {
        let config = parse_yaml(
            r#"
workspaces:
  deva:
    path: .
    processes:
      - cmd: [echo, hello]
"#,
        );
        let workspace = config.resolve_workspace("deva").expect("resolve defaults");
        assert_eq!(workspace.grace_seconds, 5);
        assert_eq!(workspace.dotenv, [".env"]);
        assert!(!workspace.envrc);
        assert_eq!(workspace.logs_lines, 200);
        assert_eq!(workspace.logs_keep_instances, 20);
        assert_eq!(workspace.logs_default, "echo");
        assert_eq!(workspace.processes[0].name, "echo");
        assert!(!workspace.processes[0].default_log);
        assert!(workspace.processes[0].default_stream.is_none());
    }

    #[test]
    fn yaml_workspace_values_override_global_defaults() {
        let config = parse_yaml(
            r#"
defaults:
  stop: {grace_seconds: 9}
  env: {dotenv: [.env.global], envrc: true}
  logs: {lines: 300, default: backend:out, keep_instances: 30}
workspaces:
  deva:
    path: .
    stop: {grace_seconds: 0}
    env: {dotenv: [], envrc: false}
    logs: {lines: 0, default: backend:err, keep_instances: 0}
    processes:
      - name: backend
        cmd: [echo, hello]
        default_log: true
        default_stream: err
"#,
        );
        assert_eq!(config.defaults.stop.grace_seconds, 9);
        assert_eq!(config.defaults.env.dotenv, [".env.global"]);
        assert!(config.defaults.env.envrc);
        assert_eq!(config.defaults.logs.lines, 300);
        assert_eq!(config.defaults.logs.default, "backend:out");
        assert_eq!(config.defaults.logs.keep_instances, 30);
        let workspace = config.resolve_workspace("deva").expect("resolve overrides");
        assert_eq!(workspace.grace_seconds, 0);
        assert!(workspace.dotenv.is_empty());
        assert!(!workspace.envrc);
        assert_eq!(workspace.logs_lines, 0);
        assert_eq!(workspace.logs_default, "backend:err");
        assert_eq!(workspace.logs_keep_instances, 0);
        assert!(workspace.processes[0].default_log);
        assert_eq!(
            workspace.processes[0].default_stream.as_deref(),
            Some("err")
        );
    }

    #[test]
    fn yaml_null_and_omitted_optional_fields_inherit_defaults() {
        for optional_fields in [
            "",
            r#"
    stop: {grace_seconds: null}
    env: {dotenv: null, envrc: ~}
    logs: {lines: null, default: null, keep_instances: null}
"#,
        ] {
            for process_fields in ["", "name: null, default_stream: ~,"] {
                let config = parse_yaml(&format!(
                    r#"
defaults:
  stop: {{grace_seconds: 9}}
  env: {{dotenv: [.env.global], envrc: true}}
  logs: {{lines: 300, default: echo:out, keep_instances: 30}}
workspaces:
  deva:
    path: .
{optional_fields}
    processes:
      - {{{process_fields} cmd: [echo, hello]}}
"#
                ));
                let raw = &config.workspaces["deva"];
                assert!(raw.stop.grace_seconds.is_none());
                assert!(raw.env.dotenv.is_none());
                assert!(raw.env.envrc.is_none());
                assert!(raw.logs.lines.is_none());
                assert!(raw.logs.default.is_none());
                assert!(raw.logs.keep_instances.is_none());
                assert!(raw.processes[0].name.is_none());
                assert!(raw.processes[0].default_stream.is_none());
                let workspace = config.resolve_workspace("deva").expect("resolve inherited");
                assert_eq!(workspace.grace_seconds, 9);
                assert_eq!(workspace.dotenv, [".env.global"]);
                assert!(workspace.envrc);
                assert_eq!(workspace.logs_lines, 300);
                assert_eq!(workspace.logs_default, "echo:out");
                assert_eq!(workspace.logs_keep_instances, 30);
            }
        }
    }

    #[test]
    fn yaml_preserves_quoted_paths_commands_and_aliases() {
        let config = parse_yaml(
            r#"
workspaces:
  deva:
    path: 'C:\Users\Some User\project'
    processes:
      - name: 'NO'
        cmd: &command ["sh", "-c", "echo 'hello: #world' && printf \"yes\""]
      - cmd: *command
  other:
    path: "/tmp/a path/#project"
"#,
        );
        let workspace = &config.workspaces["deva"];
        assert_eq!(workspace.path, r"C:\Users\Some User\project");
        assert_eq!(workspace.processes[0].name.as_deref(), Some("NO"));
        assert_eq!(
            workspace.processes[0].cmd,
            ["sh", "-c", r#"echo 'hello: #world' && printf "yes""#]
        );
        assert_eq!(workspace.processes[1].cmd, workspace.processes[0].cmd);
        assert_eq!(config.workspaces["other"].path, "/tmp/a path/#project");
        assert!(config.workspaces["other"].processes.is_empty());
    }

    #[test]
    fn yaml_rejects_invalid_types_duplicate_fields_and_documents() {
        for raw in [
            "defaults: {stop: {grace_seconds: -1}}",
            "defaults: {env: {envrc: maybe}}",
            "defaults: {env: {dotenv: .env}}",
            "defaults: {logs: {lines: null}}",
            "workspaces: []",
            "workspaces: {deva: {processes: []}}",
            "workspaces: {deva: {path: ., processes: [{cmd: echo}]}}",
            "workspaces: {deva: {path: ., processes: [{cmd: [echo], default_log: null}]}}",
            "defaults: {}\ndefaults: {}",
            "workspaces: {deva: {path: ., path: other}}",
            "workspaces: [",
            "workspaces: *undefined",
            "---\nworkspaces: {}\n---\nworkspaces: {}",
        ] {
            assert!(
                serde_norway::from_str::<Config>(raw).is_err(),
                "unexpectedly accepted {raw:?}"
            );
        }
    }

    #[test]
    fn yaml_duplicate_workspace_map_keys_keep_last_value() {
        // Struct fields reject duplicates, but HashMap deserialization keeps the last value.
        let config = parse_yaml(
            r#"
workspaces:
  deva: {path: first}
  deva: {path: second}
"#,
        );
        assert_eq!(config.workspaces.len(), 1);
        assert_eq!(config.workspaces["deva"].path, "second");
    }

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
    fn generated_process_names_do_not_collide_with_explicit_suffixes() {
        let items: Vec<_> = ["app", "app", "app-2", "app", "app-2", "app-2-2"]
            .into_iter()
            .map(|name| ProcessConfig {
                name: Some(name.to_string()),
                cmd: vec!["echo".to_string()],
                default_log: false,
                default_stream: None,
            })
            .collect();
        let resolved = resolve_processes(&items).expect("resolve colliding names");
        let names: Vec<_> = resolved
            .iter()
            .map(|process| process.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["app", "app-2", "app-2-2", "app-3", "app-2-3", "app-2-2-2"]
        );
        assert_eq!(names.iter().collect::<HashSet<_>>().len(), names.len());
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
