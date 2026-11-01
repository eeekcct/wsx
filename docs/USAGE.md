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
  - press `Ctrl+C` to stop the followed instance before exiting (a replacement
    selected or started by another terminal is not stopped)
  - on Unix, follow ends when the target's managed process group disappears and
    its final logs have been drained, even if the original launcher exits earlier;
    unrelated service groups do not keep that target's follow open
  - on Windows, completion continues to track the target process
  - on Linux, a zombie owned by another process can keep the group present and
    follow open until its parent/reaper collects it; use `q` + Enter to detach or
    `--no-follow` for a snapshot. There is no idle-output timeout that could drop
    delayed descendant output

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
- On Unix, `running` means a managed process group still exists, checked with signal zero
  (no signal is delivered). The launcher itself need not still exist.
- This is not a live-process check: Linux also reports unreaped zombies. Other Unix
  kernels may report zombie-only groups differently. Permission-denied or unexpected
  probe errors are conservatively treated as running.

## Notes

- `wsx` state is stored under `~/.config/wsx`.
- Lifecycle operations and state reconciliation are serialized across processes using
  `lifecycle.lock` in that state directory. Concurrent `up` commands cannot both start
  the same selected instance. Different state directories remain independent.
  Use this version in all terminals; older versions do not participate in locking.
- The lock covers environment loading, startup, stop confirmation, and state updates,
  not log following or the command launched by `exec`. A slow `.envrc` or stop can
  therefore delay other lifecycle commands. Do not synchronously invoke same-state-root
  `wsx` commands (other than `list`) from `.envrc`: they would wait on the caller’s lock.
  `exec` uses the workspace snapshot it
  prepared even if another terminal subsequently changes the selection.
- The OS releases the lock when its owner exits; the lock file normally remains and
  must not be deleted while commands are active. JSON files are replaced atomically
  so readers do not observe partially written documents. This is not a transaction
  across process creation and multiple files: a crash during startup can still need
  manual recovery; do not remove metadata while services may be running.
- If running-state or PID metadata is unreadable or inconsistent, lifecycle commands fail
  without deleting it or declaring the workspace stopped. Repair the metadata before
  retrying; do not delete it while managed processes may still be running. This prevents
  an uncertain state from silently permitting duplicate processes.
- On Windows, if the current instance was started by an older `wsx` that did not persist
  job tracking metadata, `wsx down` can fail during force stop. Start a new instance with
  the current version to enable job-based force stop.
- Configuration reference is in `docs/CONFIG.md`.
