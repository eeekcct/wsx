use anyhow::{Context, Result, bail};
use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use crate::process;
use crate::state::{PidEntry, PidsFile};

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

pub fn show_logs(pids_file: &PidsFile, target: &str, lines: usize, follow: bool) -> Result<()> {
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

fn show_combined(entry: &PidEntry, lines: usize, follow: bool) -> Result<()> {
    let out = PathBuf::from(&entry.out_log);
    let err = PathBuf::from(&entry.err_log);
    let combined = PathBuf::from(&entry.combined_log);

    rebuild_combined(&out, &err, &combined)?;

    print_last_lines(&combined, lines)?;

    if !follow {
        return Ok(());
    }

    let detach_rx = spawn_detach_listener();
    let mut out_pos = file_len(&out)?;
    let mut err_pos = file_len(&err)?;
    let mut combined_pos = file_len(&combined)?;

    loop {
        if should_detach(&detach_rx) {
            return Ok(());
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
                return Ok(());
            }

            print!("{}", String::from_utf8_lossy(&final_delta));
            std::io::stdout().flush().ok();
            combined_pos += final_delta.len() as u64;
        }

        thread::sleep(Duration::from_millis(250));
    }
}

fn tail_file(path: &Path, lines: usize, follow: bool, pid: u32) -> Result<()> {
    ensure_file(path)?;
    print_last_lines(path, lines)?;

    if !follow {
        return Ok(());
    }

    let detach_rx = spawn_detach_listener();
    let mut pos = file_len(path)?;
    loop {
        if should_detach(&detach_rx) {
            return Ok(());
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
                return Ok(());
            }

            print!("{}", String::from_utf8_lossy(&final_delta));
            std::io::stdout().flush().ok();
            pos += final_delta.len() as u64;
        }

        thread::sleep(Duration::from_millis(250));
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

fn spawn_detach_listener() -> Option<Receiver<()>> {
    if !std::io::stdin().is_terminal() {
        return None;
    }

    eprintln!("[wsx] following logs (press q + Enter to detach)");

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
}
