use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use uuid::Uuid;

use crate::config::ResolvedWorkspace;

// Keep sourcing out of a conditional so an explicit `set -e` in .envrc still
// works in bash. A case statement preserves the source status without exporting
// a temporary variable under `set -a`.
fn envrc_script(source_command: &str, token: &str) -> String {
    format!(
        "set -a; {source_command} ./.envrc; case $? in 0) printf '\\0wsx-env-{token}\\0'; env -0 ;; *) exit $? ;; esac"
    )
}

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
    // Separate .envrc's ordinary stdout from its resulting environment without
    // interpreting log messages as variables or introducing a shell variable.
    let token = Uuid::new_v4().to_string();
    let marker = format!("\0wsx-env-{token}\0");

    #[cfg(unix)]
    {
        let output = Command::new("sh")
            .arg("-c")
            .arg(envrc_script(".", &token))
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

        *env_map = parse_env_output(&output.stdout, marker.as_bytes())?;
    }

    #[cfg(windows)]
    {
        let output = Command::new("bash")
            .arg("-c")
            .arg(envrc_script("source", &token))
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
                *env_map = parse_env_output(&output.stdout, marker.as_bytes())?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                traxer::warn!(
                    "bash was not found on this machine; .envrc was skipped for this run"
                );
            }
            Err(err) => {
                return Err(err).context("failed to execute .envrc via bash");
            }
        }
    }

    Ok(())
}

fn parse_env_output(raw_output: &[u8], marker: &[u8]) -> Result<HashMap<String, String>> {
    let start = raw_output
        .windows(marker.len())
        .position(|window| window == marker)
        .context(".envrc did not produce an environment snapshot")?
        + marker.len();
    let raw_environment = &raw_output[start..];
    if !raw_environment.is_empty() && !raw_environment.ends_with(&[0]) {
        bail!(".envrc environment snapshot is not NUL-terminated; env must support -0");
    }
    let output = std::str::from_utf8(raw_environment)
        .context(".envrc environment snapshot is not valid UTF-8")?;
    let mut environment = HashMap::new();
    for entry in output.split_terminator('\0') {
        let (key, value) = entry
            .split_once('=')
            .filter(|(key, _)| !key.is_empty())
            .context(".envrc environment snapshot contains an invalid entry")?;
        environment.insert(key.to_string(), value.to_string());
    }
    Ok(environment)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct TestWorkspace(PathBuf);

    impl TestWorkspace {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("wsx envrc 日本語 {}", Uuid::new_v4()));
            fs::create_dir_all(&path).expect("create isolated workspace");
            Self(path)
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn initial_environment() -> HashMap<String, String> {
        HashMap::from([
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("WSX_TEST_PRIORITY".to_string(), "os".to_string()),
        ])
    }

    #[test]
    fn envrc_nonzero_source_status_aborts_without_merging_environment() {
        for failure in ["false", "return 23", "exit 23"] {
            let workspace = TestWorkspace::new();
            fs::write(
                workspace.0.join(".envrc"),
                format!("export WSX_TEST_PRIORITY=envrc\n{failure}\n"),
            )
            .expect("write failing envrc");
            let mut environment = initial_environment();
            let original = environment.clone();

            let error = apply_envrc(&workspace.0, &mut environment)
                .expect_err("nonzero envrc status must abort environment resolution");

            assert!(error.to_string().contains(".envrc execution failed"));
            assert_eq!(environment, original, "failed envrc must not be merged");
        }
    }

    #[test]
    fn successful_envrc_preserves_layering_and_workspace_directory() {
        let workspace = TestWorkspace::new();
        fs::write(
            workspace.0.join(".env"),
            "WSX_TEST_PRIORITY=dotenv\nWSX_TEST_DOTENV_ONLY=retained\n",
        )
        .expect("write dotenv");
        fs::write(
            workspace.0.join(".envrc"),
            concat!(
                "[ \"$WSX_TEST_PRIORITY\" = dotenv ] || return 81\n",
                "export WSX_TEST_PRIORITY=envrc\n",
                "export WSX_TEST_BASEDIR=\"$PWD\"\n",
            ),
        )
        .expect("write successful envrc");
        let mut environment = initial_environment();

        apply_dotenv_files(&workspace.0, &[".env".to_string()], &mut environment)
            .expect("apply dotenv layer");
        assert_eq!(environment["WSX_TEST_PRIORITY"], "dotenv");
        apply_envrc(&workspace.0, &mut environment).expect("apply envrc layer");

        assert_eq!(environment["WSX_TEST_PRIORITY"], "envrc");
        assert_eq!(environment["WSX_TEST_DOTENV_ONLY"], "retained");
        assert_eq!(
            fs::canonicalize(&environment["WSX_TEST_BASEDIR"]).expect("envrc directory exists"),
            fs::canonicalize(&workspace.0).expect("workspace directory exists"),
        );
    }

    #[test]
    fn successful_envrc_does_not_enable_global_errexit() {
        let workspace = TestWorkspace::new();
        fs::write(
            workspace.0.join(".envrc"),
            "false\nexport WSX_TEST_PRIORITY=recovered\n",
        )
        .expect("write envrc with handled failure");
        let mut environment = initial_environment();

        apply_envrc(&workspace.0, &mut environment)
            .expect("final successful status must be honored");

        assert_eq!(environment["WSX_TEST_PRIORITY"], "recovered");
    }

    #[test]
    fn shell_wrappers_preserve_failure_status_and_explicit_errexit() {
        let workspace = TestWorkspace::new();
        for (shell, source_command) in [("sh", "."), ("bash", "source")] {
            let script = envrc_script(source_command, "test-marker");
            for (body, expected_status) in [
                ("false", 1),
                ("return 23", 23),
                ("exit 23", 23),
                ("set -e\nfalse\nexport WSX_TEST_UNEXPECTED=bad", 1),
            ] {
                fs::write(workspace.0.join(".envrc"), body).expect("write envrc");
                let output = Command::new(shell)
                    .args(["-c", &script])
                    .current_dir(&workspace.0)
                    .env_clear()
                    .envs(initial_environment())
                    .output();
                let output = match output {
                    Ok(output) => output,
                    Err(err) if shell == "bash" && err.kind() == std::io::ErrorKind::NotFound => {
                        eprintln!("bash not available; skipping bash wrapper regression");
                        break;
                    }
                    Err(err) => panic!("failed to execute {shell}: {err}"),
                };

                assert_eq!(
                    output.status.code(),
                    Some(expected_status),
                    "{shell} must preserve source failure for {body:?}",
                );
                assert!(
                    output.stdout.is_empty(),
                    "{shell} must not print environment after source failure",
                );
            }
        }
    }

    #[test]
    fn envrc_removes_inherited_variables_and_preserves_multiline_values() {
        let workspace = TestWorkspace::new();
        fs::write(workspace.0.join(".env"), "WSX_TEST_DOTENV_REMOVE=dotenv\n")
            .expect("write dotenv");
        fs::write(
            workspace.0.join(".envrc"),
            concat!(
                "unset WSX_TEST_PRIORITY WSX_TEST_DOTENV_REMOVE\n",
                "export WSX_TEST_MULTILINE='first line\nsecond=value\n'\n",
                "export WSX_TEST_EMPTY=''\n",
                "printf 'WSX_TEST_FAKE=stdout-log\\n'\n",
                "printf '\\0unrelated-marker\\0'\n",
            ),
        )
        .expect("write envrc");
        let mut environment = initial_environment();
        apply_dotenv_files(&workspace.0, &[".env".to_string()], &mut environment)
            .expect("apply dotenv layer");

        apply_envrc(&workspace.0, &mut environment).expect("capture exact envrc environment");

        assert!(!environment.contains_key("WSX_TEST_PRIORITY"));
        assert!(!environment.contains_key("WSX_TEST_DOTENV_REMOVE"));
        assert!(!environment.contains_key("WSX_TEST_FAKE"));
        assert_eq!(
            environment["WSX_TEST_MULTILINE"],
            "first line\nsecond=value\n"
        );
        assert_eq!(environment["WSX_TEST_EMPTY"], "");
    }

    #[test]
    fn environment_snapshot_parser_ignores_stdout_and_rejects_invalid_transport() {
        let marker = b"\0wsx-env-test\0";
        let environment = parse_env_output(
            b"FAKE=log\n\0wsx-env-test\0VALUE=line one\nline=two\0EMPTY=\0",
            marker,
        )
        .expect("parse NUL-separated environment");
        assert_eq!(environment.len(), 2);
        assert_eq!(environment["VALUE"], "line one\nline=two");
        assert_eq!(environment["EMPTY"], "");
        assert!(parse_env_output(marker, marker).unwrap().is_empty());
        for invalid in [
            &b""[..],
            &b"VALUE=missing-marker\0"[..],
            &b"\0wsx-env-test\0VALUE=unterminated"[..],
            &b"\0wsx-env-test\0no-equals\0"[..],
            &b"\0wsx-env-test\0=value\0"[..],
            &b"\0wsx-env-test\0VALUE=\xff\0"[..],
        ] {
            assert!(parse_env_output(invalid, marker).is_err());
        }
    }
}
