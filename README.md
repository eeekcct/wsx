# wsx

A CLI tool for switching development workspaces and managing grouped processes safely.

## Status

This project is under active development.
Behavior and configuration may change until the first stable release.

## Features

- Switch workspaces with one command (`wsx <workspace>`)
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

Example:

```yaml
defaults:
  stop:
    grace_seconds: 5
  env:
    dotenv: [.env]
    envrc: false
  logs:
    lines: 200
    keep_instances: 20

workspaces:
  deva:
    path: /path/to/clone-a
    env:
      dotenv: [.env, .env.local]
      envrc: true
    logs:
      # Optional: explicit default target
      # default: backend:out
      keep_instances: 20
    processes:
      - name: frontend
        cmd: ["npm", "run", "dev"]
      - name: backend
        default_log: true
        default_stream: err
        cmd: ["go", "run", "./cmd/server"]
      - name: worker
        cmd: ["cargo", "run", "--bin", "worker"]
```

Default log target resolution order:

1. `workspace.logs.default`
2. `defaults.logs.default`
3. `processes` entry with `default_log: true`
4. The first process in `processes`

## Requirements

- A valid `~/.config/wsx/config.yaml`
- Workspace paths must exist on local machine
- Commands in `processes[].cmd` must be executable
- For `envrc: true` on Windows, `bash` is used when available; if not available, `.envrc` is skipped with warning

## License

[MIT](./LICENSE)
