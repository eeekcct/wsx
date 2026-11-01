use anyhow::{Context, Result, bail};
use signal_hook::SigId;
use signal_hook::consts::signal::SIGINT;
use signal_hook::{flag, low_level};
use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use crate::process;
use crate::state::{PidEntry, PidsFile};

const BACKOFF_MIN_MS: u64 = 100;
const BACKOFF_MAX_MS: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamKind {
    Combined,
    Out,
    Err,
}

#[derive(Debug, Clone)]
struct ParsedTarget {
    process_name: String,
    stream: StreamKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowOutcome {
    Completed,
    Detached,
    Interrupted,
}

pub fn show_logs(
    pids_file: &PidsFile,
    target: &str,
    lines: usize,
    follow: bool,
) -> Result<FollowOutcome> {
    let parsed = parse_target(target)?;
    let available = available_targets(pids_file);
    let entry = pids_file
        .entries
        .iter()
        .find(|entry| entry.name == parsed.process_name)
        .with_context(|| {
            if available.is_empty() {
                format!("process `{}` is not running", parsed.process_name)
            } else {
                format!(
                    "process `{}` is not running (available targets: {})",
                    parsed.process_name, available
                )
            }
        })?;

    match parsed.stream {
        StreamKind::Combined => show_combined(entry, lines, follow),
        StreamKind::Out => tail_file(&PathBuf::from(&entry.out_log), lines, follow, entry.pid),
        StreamKind::Err => tail_file(&PathBuf::from(&entry.err_log), lines, follow, entry.pid),
    }
}

fn show_combined(entry: &PidEntry, lines: usize, follow: bool) -> Result<FollowOutcome> {
    let out = PathBuf::from(&entry.out_log);
    let err = PathBuf::from(&entry.err_log);
    let combined = PathBuf::from(&entry.combined_log);

    let snapshot = rebuild_combined(&out, &err, &combined)?;
    print_last_lines(&snapshot.content, lines);

    if !follow {
        return Ok(FollowOutcome::Completed);
    }

    let control = FollowControl::new()?;
    let mut offsets = snapshot.offsets;
    let mut sleep_backoff = BACKOFF_MIN_MS;

    loop {
        if let Some(outcome) = control.poll()? {
            return Ok(outcome);
        }

        // Check completion before draining. If the process exits during the
        // read, the next iteration drains its final bytes using the same offsets.
        let completed = !is_pid_running(entry.pid);
        let delta = read_combined_delta(&out, &err, &mut offsets)?;
        let had_delta = !delta.is_empty();
        if had_delta {
            append_to_file(&combined, &delta)?;
            print!("{}", String::from_utf8_lossy(&delta));
            std::io::stdout().flush().ok();
        }
        if completed && !had_delta {
            return Ok(FollowOutcome::Completed);
        }

        sleep_backoff = next_backoff_ms(sleep_backoff, had_delta);
        thread::sleep(Duration::from_millis(sleep_backoff));
    }
}

fn tail_file(path: &Path, lines: usize, follow: bool, pid: u32) -> Result<FollowOutcome> {
    let snapshot = read_log_snapshot(path)?;
    print_last_lines(&snapshot, lines);

    if !follow {
        return Ok(FollowOutcome::Completed);
    }

    let control = FollowControl::new()?;
    // Advance only past bytes in the displayed snapshot. Stat'ing the file here
    // could skip bytes appended between the initial read and this offset capture.
    let mut pos = snapshot.len() as u64;
    let mut sleep_backoff = BACKOFF_MIN_MS;
    loop {
        if let Some(outcome) = control.poll()? {
            return Ok(outcome);
        }

        let completed = !is_pid_running(pid);
        let delta = read_from_offset(path, pos)?;
        let had_delta = !delta.is_empty();
        if had_delta {
            print!("{}", String::from_utf8_lossy(&delta));
            std::io::stdout().flush().ok();
            pos += delta.len() as u64;
        }
        if completed && !had_delta {
            return Ok(FollowOutcome::Completed);
        }

        sleep_backoff = next_backoff_ms(sleep_backoff, had_delta);
        thread::sleep(Duration::from_millis(sleep_backoff));
    }
}

fn parse_target(target: &str) -> Result<ParsedTarget> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        bail!("logs target is empty (expected <process>, <process>:out, or <process>:err)");
    }

    match trimmed.split_once(':') {
        Some((name, "out")) => {
            let process_name = name.trim();
            if process_name.is_empty() {
                bail!("logs target is empty (expected <process>, <process>:out, or <process>:err)");
            }
            Ok(ParsedTarget {
                process_name: process_name.to_string(),
                stream: StreamKind::Out,
            })
        }
        Some((name, "err")) => {
            let process_name = name.trim();
            if process_name.is_empty() {
                bail!("logs target is empty (expected <process>, <process>:out, or <process>:err)");
            }
            Ok(ParsedTarget {
                process_name: process_name.to_string(),
                stream: StreamKind::Err,
            })
        }
        Some((_name, stream)) => bail!(
            "invalid logs stream `{stream}` (expected out or err; target format: <process>, <process>:out, <process>:err)"
        ),
        None => Ok(ParsedTarget {
            process_name: trimmed.to_string(),
            stream: StreamKind::Combined,
        }),
    }
}

fn available_targets(pids_file: &PidsFile) -> String {
    let mut targets = Vec::new();
    for entry in &pids_file.entries {
        targets.push(entry.name.clone());
        targets.push(format!("{}:out", entry.name));
        targets.push(format!("{}:err", entry.name));
    }
    targets.join(", ")
}

#[derive(Debug, Default)]
struct CombinedOffsets {
    out: u64,
    err: u64,
}

struct CombinedSnapshot {
    content: String,
    offsets: CombinedOffsets,
}

fn rebuild_combined(out: &Path, err: &Path, combined: &Path) -> Result<CombinedSnapshot> {
    ensure_file(out)?;
    ensure_file(err)?;

    let mut bytes = fs::read(out).with_context(|| format!("failed to read {}", out.display()))?;
    let err_bytes = fs::read(err).with_context(|| format!("failed to read {}", err.display()))?;
    let offsets = CombinedOffsets {
        out: bytes.len() as u64,
        err: err_bytes.len() as u64,
    };
    bytes.extend_from_slice(&err_bytes);
    fs::write(combined, &bytes)
        .with_context(|| format!("failed to write {}", combined.display()))?;
    let content = String::from_utf8(bytes)
        .with_context(|| format!("failed to read {} as UTF-8", combined.display()))?;

    Ok(CombinedSnapshot { content, offsets })
}

fn read_combined_delta(out: &Path, err: &Path, offsets: &mut CombinedOffsets) -> Result<Vec<u8>> {
    let mut bytes = read_from_offset(out, offsets.out)?;
    let err_bytes = read_from_offset(err, offsets.err)?;
    offsets.out += bytes.len() as u64;
    offsets.err += err_bytes.len() as u64;
    bytes.extend_from_slice(&err_bytes);
    Ok(bytes)
}

fn append_to_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to append {}", path.display()))?;
    Ok(())
}

fn read_from_offset(path: &Path, offset: u64) -> Result<Vec<u8>> {
    ensure_file(path)?;

    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("failed to seek {}", path.display()))?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .with_context(|| format!("failed to read {}", path.display()))?;

    Ok(buffer)
}

fn read_log_snapshot(path: &Path) -> Result<String> {
    ensure_file(path)?;
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn print_last_lines(content: &str, lines: usize) {
    let rows: Vec<&str> = content.lines().collect();
    let start = rows.len().saturating_sub(lines);
    for row in &rows[start..] {
        println!("{row}");
    }
}

fn ensure_file(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    if !path.exists() {
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    }

    Ok(())
}

fn next_backoff_ms(current: u64, had_delta: bool) -> u64 {
    if had_delta {
        BACKOFF_MIN_MS
    } else {
        current
            .saturating_mul(2)
            .clamp(BACKOFF_MIN_MS, BACKOFF_MAX_MS)
    }
}

struct FollowControl {
    signal: SignalGuard,
    detach_rx: Option<Receiver<()>>,
}

impl FollowControl {
    fn new() -> Result<Self> {
        Ok(Self {
            signal: SignalGuard::register()?,
            detach_rx: spawn_detach_listener(),
        })
    }

    fn poll(&self) -> Result<Option<FollowOutcome>> {
        if self.signal.interrupted() {
            return Ok(Some(FollowOutcome::Interrupted));
        }

        if should_detach(&self.detach_rx) {
            return Ok(Some(FollowOutcome::Detached));
        }

        Ok(None)
    }
}

struct SignalGuard {
    signal_id: SigId,
    interrupted: Arc<AtomicBool>,
}

impl SignalGuard {
    fn register() -> Result<Self> {
        let interrupted = Arc::new(AtomicBool::new(false));
        let signal_id = flag::register(SIGINT, Arc::clone(&interrupted))
            .context("failed to register SIGINT handler")?;
        Ok(Self {
            signal_id,
            interrupted,
        })
    }

    fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::Relaxed)
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        low_level::unregister(self.signal_id);
    }
}

fn spawn_detach_listener() -> Option<Receiver<()>> {
    if !std::io::stdin().is_terminal() {
        return None;
    }

    traxer::info!("following logs (press q + Enter to detach, Ctrl+C to stop workspace)");

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let stdin = std::io::stdin();
        loop {
            let mut line = String::new();
            if stdin.read_line(&mut line).is_err() {
                break;
            }
            if line.trim().eq_ignore_ascii_case("q") {
                let _ = tx.send(());
                break;
            }
        }
    });

    Some(rx)
}

fn should_detach(detach_rx: &Option<Receiver<()>>) -> bool {
    match detach_rx {
        None => false,
        Some(rx) => match rx.try_recv() {
            Ok(_) => true,
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => false,
        },
    }
}

fn is_pid_running(pid: u32) -> bool {
    process::is_pid_running(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempLogs(PathBuf);

    impl TempLogs {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("wsx-log-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).expect("create log fixture");
            Self(path)
        }
    }

    impl Drop for TempLogs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn combined_offsets_track_the_exact_snapshot_and_drain_each_byte_once() {
        let fixture = TempLogs::new();
        let out = fixture.0.join("out.log");
        let err = fixture.0.join("err.log");
        let combined = fixture.0.join("combined.log");
        fs::write(&out, "before-out\n").expect("write stdout");
        fs::write(&err, "before-err\n").expect("write stderr");
        let snapshot = rebuild_combined(&out, &err, &combined).expect("initial snapshot");
        assert_eq!(snapshot.content, "before-out\nbefore-err\n");
        let mut offsets = snapshot.offsets;

        // These writes deliberately happen after the initial read, the race
        // window where taking fresh file lengths used to discard output.
        append_to_file(&out, b"late-out\n").expect("append stdout");
        append_to_file(&err, b"late-err\n").expect("append stderr");
        assert_eq!(
            read_combined_delta(&out, &err, &mut offsets).expect("drain final bytes"),
            b"late-out\nlate-err\n"
        );
        assert!(
            read_combined_delta(&out, &err, &mut offsets)
                .expect("repeat drain")
                .is_empty()
        );
    }

    #[test]
    fn single_stream_offset_does_not_skip_bytes_after_initial_snapshot() {
        let fixture = TempLogs::new();
        let path = fixture.0.join("out.log");
        fs::write(&path, "before\n").expect("write stdout");
        let snapshot = read_log_snapshot(&path).expect("initial snapshot");
        append_to_file(&path, "日本語 after\n".as_bytes()).expect("append stdout");
        assert_eq!(
            read_from_offset(&path, snapshot.len() as u64).expect("read new bytes"),
            "日本語 after\n".as_bytes()
        );
    }

    #[test]
    fn parses_target_formats() {
        let combined = parse_target("backend").expect("combined");
        assert_eq!(combined.process_name, "backend");
        assert_eq!(combined.stream, StreamKind::Combined);

        let out = parse_target("backend:out").expect("out");
        assert_eq!(out.stream, StreamKind::Out);

        let err = parse_target("backend:err").expect("err");
        assert_eq!(err.stream, StreamKind::Err);

        assert!(parse_target("backend:unknown").is_err());
        assert!(parse_target(":out").is_err());
    }

    #[test]
    fn backoff_increases_until_cap() {
        let mut ms = BACKOFF_MIN_MS;
        ms = next_backoff_ms(ms, false);
        assert_eq!(ms, 200);
        ms = next_backoff_ms(ms, false);
        assert_eq!(ms, 400);
        ms = next_backoff_ms(ms, false);
        assert_eq!(ms, 800);
        ms = next_backoff_ms(ms, false);
        assert_eq!(ms, BACKOFF_MAX_MS);
        ms = next_backoff_ms(ms, false);
        assert_eq!(ms, BACKOFF_MAX_MS);
    }

    #[test]
    fn backoff_resets_on_delta() {
        let ms = next_backoff_ms(800, true);
        assert_eq!(ms, BACKOFF_MIN_MS);
    }
}
