# wsx Usage

This document describes CLI usage for the current implementation.

## Command Overview

```text
wsx <workspace>
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
- Saves runtime metadata to `~/.config/wsx/current.json` and `instances/<id>/pids.json`.
- Starts log follow for the configured default log target.
- During log follow, press `q` then Enter to detach without stopping processes.

### `wsx list`

List configured workspaces in sorted order.

- Marks current workspace with `*`.

### `wsx up`

Start the current workspace when it is in `stopped` state.

- Reuses `current.workspace`.
- Generates a new `instance_id`.
- If current workspace is already running, exits without starting duplicate processes.

### `wsx down`

Stop the current running workspace.

- Sends graceful stop first, then force stop if needed.
- On Windows, graceful stop uses `taskkill`, and force stop uses Windows Job Object termination.
- If processes still remain after stop attempts, command fails.
- Keeps `current.json` and sets current state to `stopped` on success.

### `wsx logs [target] [--lines <n>] [--no-follow]`

Show logs for current workspace.

- `target` format:
  - `<process>` (combined)
  - `<process>:out`
  - `<process>:err`
- `--lines <n>` controls initial tail size.
- `--no-follow` prints initial tail and exits immediately.
- Without `--no-follow`, logs are followed:
  - press `q` then Enter to detach
  - press `Ctrl+C` to stop the current workspace before exiting
  - follow ends automatically when target process stops and no new log is appended

### `wsx exec <cmd...>`

Run an arbitrary command in the current workspace context.

- Uses current workspace directory as `cwd`.
- Applies workspace env resolution order: OS -> dotenv -> envrc.
- Passes args directly (no implicit shell wrapping).
- Shell aliases and builtins are not resolved by default.
  On Windows, `cat` is a PowerShell alias and cannot be executed directly with `wsx exec`.

Example:

```sh
wsx exec bin/rails db:migrate
```

### `wsx status`

Show runtime status.

- Current workspace name
- Current state (`running` or `stopped`)
- Current instance id and start time
- Per-process pid and `running`/`stopped`

## Notes

- `wsx` state is stored under `~/.config/wsx`.
- On Windows, if the current instance was started by an older `wsx` that did not persist
  job tracking metadata, `wsx down` can fail during force stop. Start a new instance with
  the current version to enable job-based force stop.
- Configuration reference is in `docs/CONFIG.md`.
