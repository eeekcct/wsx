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
- Saves runtime metadata to `~/.config/wsx/current.json` and `instances/<id>/pids.json`.
- Starts log follow for the configured default log target.
- During log follow, press `q` then Enter to detach without stopping processes.

### `wsx select <workspace>`

Select a workspace without starting processes.

- Stops the current running workspace first.
- Updates `current.json` to the selected workspace with `stopped` status.
- Does not create a new runtime instance or `pids.json`.

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
- If processes still remain after stop attempts, command fails. A timeout reports
  each remaining service name and saved PGID (Unix) or PID (Windows), because
  termination could not be confirmed.
- During Unix stop polling, wsx nonblockingly reaps only each saved PID if it is
  its own exited direct child. It does not enumerate or reap unrelated processes.
- On Linux, an unreaped zombie owned by another process can keep a group present even though no member is executing.
  In that case `down` can fail after the configured grace period plus approximately
  20 seconds of force-stop retries. SIGKILL cannot remove a zombie; its parent (or
  the adopting reaper) must collect its exit status.
- On such a failure, current state remains `running`, and the instance ID and
  `pids.json` are retained. A subsequent `up` reports already running without launching
  duplicates while the group still exists. Once it has been reaped and the group is
  gone, `status`/`up` can reconcile it as stopped. Workspace switching also fails
  rather than abandoning an instance that could not be stopped.
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
- Current instance id (`(none)` when no running instance) and start time
- Per-process pid and `running`/`stopped`
- On Unix, `running` means a managed process group still exists, checked with signal zero
  (no signal is delivered). The launcher itself need not still exist.
- This is not a live-process check: Linux also reports unreaped zombies. Other Unix
  kernels may report zombie-only groups differently. Permission-denied or unexpected
  probe errors are conservatively treated as running.

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
