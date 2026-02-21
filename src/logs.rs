use anyhow::{Context, Result, bail};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use signal_hook::SigId;
use signal_hook::consts::signal::SIGINT;
use signal_hook::{flag, low_level};
use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputEvent {
    Detach,
    Interrupt,
}

impl InputEvent {
    fn into_follow_outcome(self) -> FollowOutcome {
        match self {
            InputEvent::Detach => FollowOutcome::Detached,
            InputEvent::Interrupt => FollowOutcome::Interrupted,
        }
    }
}

pub fn show_logs(
    pids_file: &PidsFile,
    target: &str,
    lines: usize,
    follow: bool,
) -> Result<FollowOutcome> {
    let parsed = parse_target(target)?;
    let entry = pids_file
        .entries
        .iter()
        .find(|entry| entry.name == parsed.process_name)
        .with_context(|| format!("process `{}` is not running", parsed.process_name))?;

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

    rebuild_combined(&out, &err, &combined)?;

    print_last_lines(&combined, lines)?;

    if !follow {
        return Ok(FollowOutcome::Completed);
    }

    let mut control = FollowControl::new()?;
    let mut out_pos = file_len(&out)?;
    let mut err_pos = file_len(&err)?;
    let mut combined_pos = file_len(&combined)?;

    let mut sleep_backoff = BACKOFF_MIN_MS;

    loop {
        if let Some(outcome) = control.poll()? {
            return Ok(outcome);
        }

        let mut had_delta = false;

        let out_delta = read_from_offset(&out, out_pos)?;
        if !out_delta.is_empty() {
            append_to_file(&combined, &out_delta)?;
            out_pos += out_delta.len() as u64;
            had_delta = true;
        }

        let err_delta = read_from_offset(&err, err_pos)?;
        if !err_delta.is_empty() {
            append_to_file(&combined, &err_delta)?;
            err_pos += err_delta.len() as u64;
            had_delta = true;
        }

        let combined_delta = read_from_offset(&combined, combined_pos)?;
        if !combined_delta.is_empty() {
            print!("{}", String::from_utf8_lossy(&combined_delta));
            std::io::stdout().flush().ok();
            combined_pos += combined_delta.len() as u64;
            had_delta = true;
        }

        if !had_delta && !is_pid_running(entry.pid) {
            rebuild_combined(&out, &err, &combined)?;
            let final_delta = read_from_offset(&combined, combined_pos)?;
            if final_delta.is_empty() {
                return Ok(FollowOutcome::Completed);
            }

            print!("{}", String::from_utf8_lossy(&final_delta));
            std::io::stdout().flush().ok();
            combined_pos += final_delta.len() as u64;
        }

        sleep_backoff = next_backoff_ms(sleep_backoff, had_delta);
        thread::sleep(Duration::from_millis(sleep_backoff));
    }
}

fn tail_file(path: &Path, lines: usize, follow: bool, pid: u32) -> Result<FollowOutcome> {
    ensure_file(path)?;
    print_last_lines(path, lines)?;

    if !follow {
        return Ok(FollowOutcome::Completed);
    }

    let mut control = FollowControl::new()?;
    let mut pos = file_len(path)?;
    let mut sleep_backoff = BACKOFF_MIN_MS;
    loop {
        if let Some(outcome) = control.poll()? {
            return Ok(outcome);
        }

        let mut had_delta = false;

        let delta = read_from_offset(path, pos)?;
        if !delta.is_empty() {
            print!("{}", String::from_utf8_lossy(&delta));
            std::io::stdout().flush().ok();
            pos += delta.len() as u64;
            had_delta = true;
        }

        if !had_delta && !is_pid_running(pid) {
            let final_delta = read_from_offset(path, pos)?;
            if final_delta.is_empty() {
                return Ok(FollowOutcome::Completed);
            }

            print!("{}", String::from_utf8_lossy(&final_delta));
            std::io::stdout().flush().ok();
            pos += final_delta.len() as u64;
        }

        sleep_backoff = next_backoff_ms(sleep_backoff, had_delta);
        thread::sleep(Duration::from_millis(sleep_backoff));
    }
}

fn parse_target(target: &str) -> Result<ParsedTarget> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        bail!("logs target is empty");
    }

    match trimmed.split_once(':') {
        Some((name, "out")) => Ok(ParsedTarget {
            process_name: name.trim().to_string(),
            stream: StreamKind::Out,
        }),
        Some((name, "err")) => Ok(ParsedTarget {
            process_name: name.trim().to_string(),
            stream: StreamKind::Err,
        }),
        Some((_name, stream)) => bail!("invalid logs stream `{stream}` (expected out or err)"),
        None => Ok(ParsedTarget {
            process_name: trimmed.to_string(),
            stream: StreamKind::Combined,
        }),
    }
}

fn rebuild_combined(out: &Path, err: &Path, combined: &Path) -> Result<()> {
    ensure_file(out)?;
    ensure_file(err)?;

    let out_bytes = fs::read(out).with_context(|| format!("failed to read {}", out.display()))?;
    let err_bytes = fs::read(err).with_context(|| format!("failed to read {}", err.display()))?;

    let mut file = File::create(combined)
        .with_context(|| format!("failed to create {}", combined.display()))?;
    file.write_all(&out_bytes)
        .with_context(|| format!("failed to write {}", combined.display()))?;
    file.write_all(&err_bytes)
        .with_context(|| format!("failed to write {}", combined.display()))?;

    Ok(())
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

fn print_last_lines(path: &Path, lines: usize) -> Result<()> {
    ensure_file(path)?;

    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let rows: Vec<&str> = content.lines().collect();

    let start = rows.len().saturating_sub(lines);
    for row in &rows[start..] {
        println!("{row}");
    }

    Ok(())
}

fn file_len(path: &Path) -> Result<u64> {
    ensure_file(path)?;
    Ok(fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .len())
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
    input: Option<InputControl>,
}

impl FollowControl {
    fn new() -> Result<Self> {
        Ok(Self {
            signal: SignalGuard::register()?,
            input: InputControl::new()?,
        })
    }

    fn poll(&mut self) -> Result<Option<FollowOutcome>> {
        if self.signal.interrupted() {
            return Ok(Some(FollowOutcome::Interrupted));
        }

        if let Some(input) = &mut self.input
            && let Some(event) = input.poll()?
        {
            return Ok(Some(event.into_follow_outcome()));
        }

        Ok(None)
    }
}

struct InputControl {
    _raw_mode: RawModeGuard,
    awaiting_detach_confirm: bool,
}

impl InputControl {
    fn new() -> Result<Option<Self>> {
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }

        eprintln!("[wsx] following logs (press q + Enter to detach, Ctrl+C to stop workspace)");
        let raw_mode = RawModeGuard::new()?;

        Ok(Some(Self {
            _raw_mode: raw_mode,
            awaiting_detach_confirm: false,
        }))
    }

    fn poll(&mut self) -> Result<Option<InputEvent>> {
        while event::poll(Duration::from_millis(0)).context("failed to poll terminal input")? {
            let event = event::read().context("failed to read terminal input")?;
            let Event::Key(key_event) = event else {
                continue;
            };

            if let Some(input_event) =
                parse_input_event(key_event, &mut self.awaiting_detach_confirm)
            {
                return Ok(Some(input_event));
            }
        }

        Ok(None)
    }
}

struct RawModeGuard {
    enabled: bool,
}

impl RawModeGuard {
    fn new() -> Result<Self> {
        enable_raw_mode().context("failed to enable terminal raw mode")?;
        Ok(Self { enabled: true })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.enabled {
            let _ = disable_raw_mode();
        }
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

fn parse_input_event(
    key_event: KeyEvent,
    awaiting_detach_confirm: &mut bool,
) -> Option<InputEvent> {
    if !matches!(key_event.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return None;
    }

    if is_ctrl_c_event(&key_event) {
        *awaiting_detach_confirm = false;
        return Some(InputEvent::Interrupt);
    }

    if *awaiting_detach_confirm {
        if is_enter_key(&key_event) {
            *awaiting_detach_confirm = false;
            return Some(InputEvent::Detach);
        }

        if is_q_key(&key_event) {
            return None;
        }

        *awaiting_detach_confirm = false;
        return None;
    }

    if is_q_key(&key_event) {
        *awaiting_detach_confirm = true;
    }

    None
}

fn is_ctrl_c_event(key_event: &KeyEvent) -> bool {
    if key_event.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key_event.code, KeyCode::Char('c') | KeyCode::Char('C'))
    {
        return true;
    }

    // Some Windows terminals in raw mode emit Ctrl+C as ETX without CONTROL modifier.
    matches!(key_event.code, KeyCode::Char('\u{3}'))
}

fn is_q_key(key_event: &KeyEvent) -> bool {
    if !matches!(
        key_event.modifiers,
        KeyModifiers::NONE | KeyModifiers::SHIFT
    ) {
        return false;
    }

    matches!(key_event.code, KeyCode::Char('q') | KeyCode::Char('Q'))
}

fn is_enter_key(key_event: &KeyEvent) -> bool {
    if matches!(key_event.modifiers, KeyModifiers::NONE) {
        return matches!(
            key_event.code,
            KeyCode::Enter | KeyCode::Char('\n') | KeyCode::Char('\r')
        );
    }

    if key_event.modifiers == KeyModifiers::CONTROL {
        // PTY input can represent Enter/newline as Ctrl+M (CR) or Ctrl+J (LF).
        return matches!(
            key_event.code,
            KeyCode::Char('m') | KeyCode::Char('M') | KeyCode::Char('j') | KeyCode::Char('J')
        );
    }

    false
}

fn is_pid_running(pid: u32) -> bool {
    process::is_pid_running(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

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

    #[test]
    fn input_state_machine_detaches_on_q_then_enter() {
        let mut awaiting_detach_confirm = false;

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            None
        );
        assert!(awaiting_detach_confirm);

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            Some(InputEvent::Detach)
        );
        assert!(!awaiting_detach_confirm);
    }

    #[test]
    fn input_state_machine_detaches_on_q_then_newline_char() {
        let mut awaiting_detach_confirm = false;

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            None
        );
        assert!(awaiting_detach_confirm);

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('\n'), KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            Some(InputEvent::Detach)
        );
        assert!(!awaiting_detach_confirm);
    }

    #[test]
    fn input_state_machine_detaches_on_q_then_ctrl_m() {
        let mut awaiting_detach_confirm = false;

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            None
        );
        assert!(awaiting_detach_confirm);

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('m'), KeyModifiers::CONTROL),
                &mut awaiting_detach_confirm
            ),
            Some(InputEvent::Detach)
        );
        assert!(!awaiting_detach_confirm);
    }

    #[test]
    fn input_state_machine_detaches_on_q_then_ctrl_j() {
        let mut awaiting_detach_confirm = false;

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            None
        );
        assert!(awaiting_detach_confirm);

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('j'), KeyModifiers::CONTROL),
                &mut awaiting_detach_confirm
            ),
            Some(InputEvent::Detach)
        );
        assert!(!awaiting_detach_confirm);
    }

    #[test]
    fn input_state_machine_interrupts_immediately_on_ctrl_c() {
        let mut awaiting_detach_confirm = true;

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                &mut awaiting_detach_confirm
            ),
            Some(InputEvent::Interrupt)
        );
        assert!(!awaiting_detach_confirm);
    }

    #[test]
    fn input_state_machine_interrupts_on_ctrl_c_etx_char() {
        let mut awaiting_detach_confirm = true;

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('\u{3}'), KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            Some(InputEvent::Interrupt)
        );
        assert!(!awaiting_detach_confirm);
    }

    #[test]
    fn input_state_machine_cancels_q_on_other_key() {
        let mut awaiting_detach_confirm = false;

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            None
        );
        assert!(awaiting_detach_confirm);

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            None
        );
        assert!(!awaiting_detach_confirm);

        assert_eq!(
            parse_input_event(
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                &mut awaiting_detach_confirm
            ),
            None
        );
    }
}
