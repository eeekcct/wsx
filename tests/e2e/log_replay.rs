#[cfg(target_os = "linux")]
mod log_replay_e2e {
    use std::fs;
    use std::path::PathBuf;
    use std::process::{Command, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
    }

    impl Fixture {
        fn new(default_stream: Option<&str>, script: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("wsx-log-replay-{}", uuid::Uuid::new_v4()));
            let home = root.join("home");
            let workspace = root.join("workspace");
            fs::create_dir_all(home.join(".config/wsx")).expect("create isolated config directory");
            fs::create_dir_all(&workspace).expect("create workspace");
            let config = serde_json::json!({
                "defaults": {"stop": {"grace_seconds": 0}, "env": {"dotenv": []}},
                "workspaces": {"demo": {
                    "path": workspace,
                    "processes": [{
                        "name": "app", "default_stream": default_stream,
                        "cmd": ["/bin/sh", "-c", script]
                    }]
                }}
            });
            fs::write(
                home.join(".config/wsx/config.yaml"),
                serde_json::to_string(&config).expect("serialize config"),
            )
            .expect("write config");
            Self { root, home }
        }

        fn run(&self, args: &[&str]) -> Output {
            let mut child = Command::new(env!("CARGO_BIN_EXE_wsx"))
                .args(args)
                .current_dir(&self.root)
                .env_clear()
                .env("HOME", &self.home)
                .env("PATH", "/usr/bin:/bin")
                .env("WSX_LOG", "error")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run wsx");
            let deadline = Instant::now() + Duration::from_secs(5);
            let timed_out = loop {
                if child.try_wait().expect("poll wsx").is_some() {
                    break false;
                }
                if Instant::now() >= deadline {
                    child.kill().expect("terminate stalled wsx");
                    break true;
                }
                thread::sleep(Duration::from_millis(5));
            };
            let output = child.wait_with_output().expect("collect wsx output");
            assert!(
                !timed_out && output.status.success(),
                "wsx {args:?} failed (timeout={timed_out}): stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            output
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn assert_once(output: &Output, marker: &str) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.lines().filter(|line| *line == marker).count(),
            1,
            "expected exactly one {marker:?}, got: {stdout}"
        );
    }

    #[test]
    fn combined_follow_emits_short_process_output_once() {
        for delay in ["", "sleep 0.01;"] {
            let fixture = Fixture::new(
                None,
                &format!("printf 'REPLAY_OUT\\n'; {delay} printf 'REPLAY_ERR\\n' >&2"),
            );
            // Immediate and just-before-exit writes exercise both the initial
            // snapshot and the final-drain windows without a long-running app.
            for _ in 0..8 {
                let start = fixture.run(&["demo"]);
                assert_once(&start, "REPLAY_OUT");
                assert_once(&start, "REPLAY_ERR");
                let stored = fixture.run(&["logs", "app", "--no-follow"]);
                assert_once(&stored, "REPLAY_OUT");
                assert_once(&stored, "REPLAY_ERR");
            }
        }
    }

    #[test]
    fn stream_follow_keeps_initial_and_final_output_without_replay() {
        for (stream, marker) in [("out", "OUT"), ("err", "ERR")] {
            let fixture = Fixture::new(
                Some(stream),
                "printf 'OUT_INITIAL\\n'; printf 'ERR_INITIAL\\n' >&2; sleep 0.01; \
                 printf 'OUT_FINAL\\n'; printf 'ERR_FINAL\\n' >&2",
            );
            for _ in 0..4 {
                let start = fixture.run(&["demo"]);
                assert_once(&start, &format!("{marker}_INITIAL"));
                assert_once(&start, &format!("{marker}_FINAL"));
                let tail = fixture.run(&[
                    "logs",
                    &format!("app:{stream}"),
                    "--no-follow",
                    "--lines",
                    "1",
                ]);
                assert_eq!(
                    String::from_utf8_lossy(&tail.stdout),
                    format!("{marker}_FINAL\n")
                );
            }
        }
    }
}
