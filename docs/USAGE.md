# wsx Usage

This document describes CLI usage for the current implementation.

## Command Overview

```text
wsx <workspace>
wsx select <workspace>
wsx list
wsx up
wsx down
wsx logs [target] [--lines <n>] [--no-follow]
wsx exec <cmd...>
wsx status
```

## Commands

### `wsx <workspace>`

Switch to a workspace.

- Stops the current running workspace first.
- Starts the target workspace processes.
- Invalid target configuration is rejected before stopping the current workspace.
- If environment loading or process startup fails after the current workspace is stopped,
  the previous workspace remains stopped; it is not restarted automatically.
- Failed startup rolls back processes already started for the target workspace.
  If rollback itself fails, the error includes that failure rather than hiding it.
- On successful startup, saves the canonical absolute workspace path and runtime metadata
  to `~/.config/wsx/current.json` and `instances/<id>/pids.json`.
- Starts log follow for the configured default log target.
- During log follow, press `q` then Enter to detach without stopping processes.

### `wsx select <workspace>`

Select a workspace without starting processes.

- Stops the current running workspace first.
- Resolves relative workspace paths from this command's working directory.
- Updates `current.json` with the selected canonical absolute directory and `stopped` status.
- Selecting again deliberately resolves the configured path again from the new working directory.
- Does not create a new runtime instance or `pids.json`.

### `wsx list`

List configured workspaces in sorted order.

- Marks current workspace with `*`.

### `wsx up`

Start the current workspace when it is in `stopped` state.

- Reuses `current.workspace` and its saved absolute directory, not the caller's directory.
- Generates a new `instance_id`.
- If current workspace is already running, exits without starting duplicate processes.

### `wsx down`

Stop the current running workspace.

- Sends graceful stop first, then force stop if needed.
- On Windows, graceful stop uses `taskkill`, and force stop uses Windows Job Object termination.
- If processes still remain after stop attempts, command fails.
- Keeps `current.json` and sets current state to `stopped` on success.
- If there is no running instance, prints a notice and exits successfully.

### `wsx logs [target] [--lines <n>] [--no-follow]`

Show logs for current workspace.

- `target` format:
  - `<process>` (combined)
  - `<process>:out`
  - `<process>:err`
- `--lines <n>` controls initial tail size.
- `--no-follow` prints initial tail and exits immediately.
- If the current workspace has no running instance, prints a notice and exits successfully.
- Without `--no-follow`, logs are followed:
  - press `q` then Enter to detach
  - press `Ctrl+C` to stop the current workspace before exiting
  - follow ends automatically when target process stops and no new log is appended

### `wsx exec <cmd...>`

Run an arbitrary command in the current workspace context.

- Uses the directory saved when the current workspace was selected as `cwd`.
- Applies workspace env resolution order: OS -> dotenv -> envrc.
- Requires a command; omitting it is a usage error (exit status `2`).
- Passes args directly (no implicit shell wrapping).
- Normal child exit codes are propagated. Spawn failures and signal termination return `1`.
- Shell aliases and builtins are not resolved by default.
  On Windows, `cat` is a PowerShell alias and cannot be executed directly with `wsx exec`.
- On Windows, use absolute executable paths and absolute `PATH` entries for reliable
  program lookup. This is separate from the application's working directory, which
  is the selected workspace.

Example:

```sh
wsx exec bin/rails db:migrate
```

### `wsx status`

Show runtime status.

- Current workspace name and saved absolute path (when available)
- Current state (`running` or `stopped`)
- Current instance id (`(none)` when no running instance) and start time
- Per-process pid and `running`/`stopped`
- On Unix, a workspace remains `running` while any managed process-group member is alive,
  even after its launcher exits.

## Notes

- `wsx` state is stored under `~/.config/wsx`.
- If running-state or PID metadata is unreadable or inconsistent, lifecycle commands fail
  without deleting it or declaring the workspace stopped. Repair the metadata before
  retrying; do not delete it while managed processes may still be running. This prevents
  an uncertain state from silently permitting duplicate processes.
- On Windows, if the current instance was started by an older `wsx` that did not persist
  job tracking metadata, `wsx down` can fail during force stop. Start a new instance with
  the current version to enable job-based force stop.
- Configuration reference is in `docs/CONFIG.md`.
