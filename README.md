# wsx

A CLI tool for switching development workspaces and managing grouped processes safely.

## Status

This project is under active development.
Behavior and configuration may change until the first stable release.
It is not production-ready yet, and some commands may fail depending on environment or incomplete features.

## Features

- Switch workspaces with one command (`wsx <workspace>`)
- List configured workspaces (`wsx list`)
- Start/stop multiple processes per workspace
- Stop the current workspace before starting the next one
- Apply environment variables in order: OS -> dotenv -> envrc
- View logs by default target, process, or stream (`combined` / `out` / `err`)
- Persist runtime state outside repositories (`~/.config/wsx`)
- Keep only recent instance logs via `logs.keep_instances`

## Installation

Download pre-built binaries from [Releases](https://github.com/eeekcct/wsx/releases).

Build from source (optional):

```sh
cargo build --release
```

Binary path:

```text
target/release/wsx
```

Or run directly during development:

```sh
cargo run -- <args>
```

## Usage

```sh
# Switch to workspace "deva"
wsx deva

# List configured workspaces
wsx list

# Show default log target
wsx logs

# Show combined logs for backend
wsx logs backend

# Show stderr only
wsx logs backend:err

# Show current workspace/process status
wsx status

# Stop current workspace
wsx down
```

## Configuration

Config file location:

```text
~/.config/wsx/config.yaml
```

Minimal example:

```yaml
defaults:
  env:
    dotenv: [.env]
    envrc: false

workspaces:
  deva:
    path: /path/to/clone-a
    processes:
      - name: backend
        cmd: ["go", "run", "./cmd/server"]
```

Full config reference:

- `docs/CONFIG.md`

## Requirements

- A valid `~/.config/wsx/config.yaml`
- Workspace paths must exist on local machine
- Commands in `processes[].cmd` must be executable
- For `envrc: true` on Windows, `bash` is used when available; if not available, `.envrc` is skipped with warning

## License

[MIT](./LICENSE)
