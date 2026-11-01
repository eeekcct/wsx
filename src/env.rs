use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::config::ResolvedWorkspace;

// Source outside conditionals to preserve explicit `set -e` behavior.
fn envrc_script(source_command: &str) -> String {
    format!(
        "exec 3>&1 1>&2; set -a; {source_command} ./.envrc 3>&-; case $? in 0) printf '\\0' >&3; env -0 >&3 ;; *) exit $? ;; esac"
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

    #[cfg(unix)]
    {
        let output = Command::new("sh")
            .arg("-c")
            .arg(envrc_script("."))
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

        *env_map = parse_env_output(&output.stdout)?;
    }

    #[cfg(windows)]
    {
        let output = Command::new("bash")
            .arg("-c")
            .arg(envrc_script("source"))
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
                *env_map = parse_env_output(&output.stdout)?;
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

fn parse_env_output(raw_output: &[u8]) -> Result<HashMap<String, String>> {
    let raw_environment = raw_output
        .strip_prefix(&[0])
        .with_context(|| {
            if raw_output.is_empty() {
                ".envrc did not produce an environment snapshot"
            } else {
                ".envrc produced unexpected stdout before the environment snapshot; check shell startup hooks"
            }
        })?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

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
        #[cfg(unix)]
        let path = "/usr/bin:/bin".to_string();
        #[cfg(windows)]
        let path = std::env::var("PATH").expect("PATH is needed to find native Bash and env");
        #[allow(unused_mut)]
        let mut environment = HashMap::from([
            ("PATH".to_string(), path),
            ("WSX_TEST_PRIORITY".to_string(), "os".to_string()),
        ]);
        #[cfg(windows)]
        environment.insert(
            "SystemRoot".to_string(),
            std::env::var("SystemRoot").expect("Windows system directory"),
        );
        environment
    }

    fn shell_wrappers() -> &'static [(&'static str, &'static str)] {
        #[cfg(unix)]
        {
            &[("sh", "."), ("bash", "source")]
        }
        #[cfg(windows)]
        {
            &[("bash", "source")]
        }
    }

    fn run_wrapper(
        workspace: &TestWorkspace,
        shell: &str,
        source_command: &str,
    ) -> Option<std::process::Output> {
        run_wrapper_with_environment(workspace, shell, source_command, initial_environment())
    }

    fn run_wrapper_with_environment(
        workspace: &TestWorkspace,
        shell: &str,
        source_command: &str,
        environment: HashMap<String, String>,
    ) -> Option<std::process::Output> {
        match Command::new(shell)
            .args(["-c", &envrc_script(source_command)])
            .current_dir(&workspace.0)
            .env_clear()
            .envs(environment)
            .output()
        {
            Ok(output) => Some(output),
            // Bash is optional on Unix, but Windows regression tests must run it.
            Err(err)
                if cfg!(unix) && shell == "bash" && err.kind() == std::io::ErrorKind::NotFound =>
            {
                eprintln!("bash not available; skipping bash wrapper regression");
                None
            }
            Err(err) => panic!("failed to execute {shell}: {err}"),
        }
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
        let cwd_marker = Uuid::new_v4().to_string();
        fs::write(workspace.0.join("cwd-marker"), &cwd_marker).expect("write cwd marker");
        fs::write(
            workspace.0.join(".envrc"),
            concat!(
                "[ \"$WSX_TEST_PRIORITY\" = dotenv ] || return 81\n",
                "[ \"$PWD\" -ef \"$WSX_TEST_EXPECTED_DIRECTORY\" ] || return 82\n",
                "export WSX_TEST_CWD_MARKER=\"$(cat ./cwd-marker)\"\n",
                "export WSX_TEST_PRIORITY=envrc\n",
                "export WSX_TEST_BASEDIR=\"$PWD\"\n",
            ),
        )
        .expect("write successful envrc");
        let mut environment = initial_environment();
        // Compare directory identity in-shell across Windows/POSIX path formats.
        environment.insert(
            "WSX_TEST_EXPECTED_DIRECTORY".to_string(),
            workspace.0.to_string_lossy().replace('\\', "/"),
        );

        apply_dotenv_files(&workspace.0, &[".env".to_string()], &mut environment)
            .expect("apply dotenv layer");
        assert_eq!(environment["WSX_TEST_PRIORITY"], "dotenv");
        apply_envrc(&workspace.0, &mut environment).expect("apply envrc layer");

        assert_eq!(environment["WSX_TEST_PRIORITY"], "envrc");
        assert_eq!(environment["WSX_TEST_DOTENV_ONLY"], "retained");
        assert_eq!(environment["WSX_TEST_CWD_MARKER"], cwd_marker);
        #[cfg(unix)]
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
        for &(shell, source_command) in shell_wrappers() {
            for (body, expected_status) in [
                ("false", 1),
                ("return 23", 23),
                ("exit 23", 23),
                ("set -e\nfalse\nexport WSX_TEST_UNEXPECTED=bad", 1),
            ] {
                fs::write(workspace.0.join(".envrc"), body).expect("write envrc");
                let Some(output) = run_wrapper(&workspace, shell, source_command) else {
                    break;
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
    fn shell_wrappers_separate_stdout_logs_from_environment_and_preserve_stderr() {
        let workspace = TestWorkspace::new();
        fs::write(
            workspace.0.join(".envrc"),
            concat!(
                "false\n",
                "unset WSX_TEST_PRIORITY\n",
                "export WSX_TEST_MULTILINE='first line\nsecond=value\n'\n",
                "export WSX_TEST_EMPTY=''\n",
                "printf 'WSX_TEST_FAKE=stdout-log\\nnext=line\\n\\0binary-log\\0'\n",
                "printf 'stderr diagnostic\\n' >&2\n",
                "trap 'printf \"exit diagnostic\\n\"' EXIT\n",
            ),
        )
        .expect("write noisy envrc");

        for &(shell, source_command) in shell_wrappers() {
            let Some(output) = run_wrapper(&workspace, shell, source_command) else {
                continue;
            };
            assert!(output.status.success(), "{shell}: {:?}", output.stderr);
            assert_eq!(
                output.stderr,
                b"WSX_TEST_FAKE=stdout-log\nnext=line\n\0binary-log\0stderr diagnostic\nexit diagnostic\n",
                "{shell} must send ordinary stdout and stderr to diagnostics",
            );
            let environment = parse_env_output(&output.stdout).expect("parse clean snapshot");
            assert!(!environment.contains_key("WSX_TEST_PRIORITY"));
            assert!(!environment.contains_key("WSX_TEST_FAKE"));
            assert!(!environment.contains_key("next"));
            assert_eq!(
                environment["WSX_TEST_MULTILINE"],
                "first line\nsecond=value\n"
            );
            assert_eq!(environment["WSX_TEST_EMPTY"], "");
        }
    }

    #[test]
    fn envrc_failure_includes_stdout_and_stderr_diagnostics() {
        let workspace = TestWorkspace::new();
        fs::write(
            workspace.0.join(".envrc"),
            "printf 'stdout diagnostic\\n'\nprintf 'stderr diagnostic\\n' >&2\nreturn 23\n",
        )
        .expect("write failing noisy envrc");
        let mut environment = initial_environment();
        let original = environment.clone();

        let error = apply_envrc(&workspace.0, &mut environment).expect_err("source must fail");

        assert!(
            error
                .to_string()
                .contains("stdout diagnostic\nstderr diagnostic")
        );
        assert_eq!(environment, original);
    }

    #[test]
    fn envrc_early_successful_exit_does_not_apply_an_empty_snapshot() {
        let workspace = TestWorkspace::new();
        fs::write(workspace.0.join(".envrc"), "exit 0\n").expect("write early-exit envrc");
        let mut environment = initial_environment();
        let original = environment.clone();

        let error = apply_envrc(&workspace.0, &mut environment)
            .expect_err("successful exit before capture must not look like an empty environment");

        assert!(
            error
                .to_string()
                .contains("did not produce an environment snapshot")
        );
        assert_eq!(environment, original);
        for &(shell, source_command) in shell_wrappers() {
            let Some(output) = run_wrapper(&workspace, shell, source_command) else {
                continue;
            };
            assert!(output.status.success());
            assert!(output.stdout.is_empty());
            assert!(parse_env_output(&output.stdout).is_err());
        }
    }

    #[test]
    fn envrc_missing_env_command_fails_without_replacing_environment() {
        let workspace = TestWorkspace::new();
        // An empty PATH searches only this fixture directory, which has no env.
        fs::write(workspace.0.join(".envrc"), "export PATH=\n")
            .expect("write envrc removing command search path");
        let mut environment = initial_environment();
        let original = environment.clone();

        let error = apply_envrc(&workspace.0, &mut environment)
            .expect_err("missing env command must fail environment capture");

        assert!(error.to_string().contains(".envrc execution failed"));
        assert_eq!(environment, original);
        for &(shell, source_command) in shell_wrappers() {
            let Some(output) = run_wrapper(&workspace, shell, source_command) else {
                continue;
            };
            assert_eq!(output.status.code(), Some(127), "{shell}");
            assert!(String::from_utf8_lossy(&output.stderr).contains("env"));
        }
    }

    #[test]
    fn envrc_invalid_snapshot_does_not_replace_environment() {
        let workspace = TestWorkspace::new();
        for body in [
            "env() { printf 'VALUE=unterminated'; }\n",
            "env() { printf 'no-equals\\0'; }\n",
        ] {
            fs::write(workspace.0.join(".envrc"), body).expect("write invalid snapshot fixture");
            let mut environment = initial_environment();
            let original = environment.clone();

            let error = apply_envrc(&workspace.0, &mut environment)
                .expect_err("malformed snapshot must fail environment capture");

            assert!(error.to_string().contains("environment snapshot"));
            assert_eq!(environment, original);
        }
    }

    #[test]
    fn shell_wrappers_wait_for_inherited_capture_pipes() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        for &(shell, source_command) in shell_wrappers() {
            for (child_start, child_end, redirections, must_wait_for_release) in [
                ("sh -c '", "'", "</dev/null >/dev/null 2>&1", false),
                ("{", "}", "</dev/null", true),
            ] {
                let workspace = TestWorkspace::new();
                fs::write(
                    workspace.0.join(".envrc"),
                    format!(
                        "{child_start}\n{}\n{child_end} {redirections} &\n{}",
                        concat!(
                            "  : > child-started\n",
                            "  attempt=0\n",
                            "  while [ ! -e child-release ] && [ \"$attempt\" -lt 60 ]; do\n",
                            "    sleep 1\n",
                            "    attempt=$((attempt + 1))\n",
                            "  done\n",
                            "  : > child-done",
                        ),
                        concat!(
                            "attempt=0\n",
                            "while [ ! -e child-started ] && [ \"$attempt\" -lt 60 ]; do\n",
                            "  sleep 0.1\n",
                            "  attempt=$((attempt + 1))\n",
                            "done\n",
                            "test -e child-started || return 89\n",
                            "trap ': > wrapper-exited' EXIT\n",
                        ),
                    ),
                )
                .expect("write background-child fixture");

                let (wrapper_exited, finished_before_release, output) =
                    std::thread::scope(|scope| {
                        let (sender, receiver) = mpsc::channel();
                        let workspace_ref = &workspace;
                        let worker = scope.spawn(move || {
                            let _ = sender.send(run_wrapper(workspace_ref, shell, source_command));
                        });
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while !workspace.0.join("wrapper-exited").exists()
                            && Instant::now() < deadline
                        {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        let wrapper_exited = workspace.0.join("wrapper-exited").exists();
                        let received = receiver.recv_timeout(Duration::from_secs(5));
                        let finished_before_release = received.is_ok();
                        // Release inherited pipes even if capture is still blocked.
                        fs::write(workspace.0.join("child-release"), "")
                            .expect("release background child");
                        let output = received.unwrap_or_else(|_| {
                            receiver
                                .recv_timeout(Duration::from_secs(5))
                                .expect("capture must finish once background child is released")
                        });
                        worker.join().expect("wrapper worker thread");
                        (wrapper_exited, finished_before_release, output)
                    });
                let Some(output) = output else {
                    continue;
                };
                let deadline = Instant::now() + Duration::from_secs(5);
                while !workspace.0.join("child-done").exists() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
                assert!(
                    workspace.0.join("child-done").exists(),
                    "{shell}: child cleanup"
                );
                assert!(wrapper_exited, "{shell}: wrapper must reach shell exit");
                assert!(output.status.success(), "{shell}: {:?}", output.stderr);
                assert!(parse_env_output(&output.stdout).is_ok());
                if must_wait_for_release {
                    assert!(
                        !finished_before_release,
                        "{shell}: inherited capture pipes must reach EOF before returning",
                    );
                }
                // Saved descriptors make fully redirected child timing shell-specific.
            }
        }
    }

    #[test]
    fn delayed_background_environment_output_stays_out_of_parent_snapshot() {
        let workspace = TestWorkspace::new();
        fs::write(
            workspace.0.join(".envrc"),
            concat!(
                "( sleep 0.1; export WSX_TEST_CHILD=child; env -0 ) &\n",
                "export WSX_TEST_PARENT=parent\n",
            ),
        )
        .expect("write delayed background-output fixture");

        for &(shell, source_command) in shell_wrappers() {
            let Some(output) = run_wrapper(&workspace, shell, source_command) else {
                continue;
            };
            assert!(output.status.success(), "{shell}");
            let environment = parse_env_output(&output.stdout).expect("parent snapshot");
            assert_eq!(environment["WSX_TEST_PARENT"], "parent");
            assert!(!environment.contains_key("WSX_TEST_CHILD"));
            // Delayed child stdout is diagnostic output, not the parent snapshot.
            let diagnostic_environment = parse_env_output(&[&b"\0"[..], &output.stderr].concat())
                .expect("child environment emitted only to stderr");
            assert_eq!(diagnostic_environment["WSX_TEST_CHILD"], "child");
        }
    }

    #[test]
    fn bash_startup_stdout_is_rejected_instead_of_treated_as_snapshot_data() {
        let workspace = TestWorkspace::new();
        let startup = workspace.0.join("bash-startup");
        fs::write(&startup, "printf 'startup log\\n'\n").expect("write Bash startup hook");
        fs::write(
            workspace.0.join(".envrc"),
            "export WSX_TEST_PRIORITY=envrc\n",
        )
        .expect("write successful envrc");
        let mut environment = initial_environment();
        // Git Bash accepts drive-letter paths with forward slashes.
        environment.insert(
            "BASH_ENV".to_string(),
            startup.to_string_lossy().replace('\\', "/"),
        );

        let Some(output) =
            run_wrapper_with_environment(&workspace, "bash", "source", environment.clone())
        else {
            return;
        };

        assert!(output.status.success());
        assert!(output.stdout.starts_with(b"startup log\n\0"));
        let error = parse_env_output(&output.stdout).expect_err("startup output must fail closed");
        assert!(error.to_string().contains("unexpected stdout"));
        #[cfg(windows)]
        {
            let original = environment.clone();
            let error = apply_envrc(&workspace.0, &mut environment)
                .expect_err("startup output must not replace the environment");
            assert!(error.to_string().contains("unexpected stdout"));
            assert_eq!(environment, original);
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_bash_runs_the_environment_wrapper() {
        let workspace = TestWorkspace::new();
        fs::write(
            workspace.0.join(".envrc"),
            "export WSX_TEST_BASH_VERSION=\"$BASH_VERSION\"\nexport WSX_TEST_OSTYPE=\"$OSTYPE\"\n",
        )
        .expect("write native Bash fixture");
        let mut environment = initial_environment();

        apply_envrc(&workspace.0, &mut environment).expect("run Windows production Bash wrapper");

        assert!(!environment["WSX_TEST_BASH_VERSION"].is_empty());
        assert!(
            matches!(environment["WSX_TEST_OSTYPE"].as_str(), "msys" | "cygwin"),
            "must use native Windows Bash, not WSL: {}",
            environment["WSX_TEST_OSTYPE"],
        );
    }

    #[test]
    fn environment_snapshot_parser_requires_frame_and_rejects_invalid_transport() {
        let environment = parse_env_output(b"\0VALUE=line one\nline=two\0EMPTY=\0")
            .expect("parse NUL-separated environment");
        assert_eq!(environment.len(), 2);
        assert_eq!(environment["VALUE"], "line one\nline=two");
        assert_eq!(environment["EMPTY"], "");
        assert!(parse_env_output(b"\0").unwrap().is_empty());
        for invalid in [
            &b""[..],
            &b"VALUE=missing-frame\0"[..],
            &b"FAKE=log\n\0VALUE=valid\0"[..],
            &b"\0VALUE=unterminated"[..],
            &b"\0no-equals\0"[..],
            &b"\0=value\0"[..],
            &b"\0VALUE=\xff\0"[..],
            &b"\0VALUE=valid\0\0"[..],
        ] {
            assert!(parse_env_output(invalid).is_err(), "accepted {invalid:?}");
        }
    }
}
