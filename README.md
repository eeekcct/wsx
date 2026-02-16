# wsx

A CLI tool for switching development workspaces and managing grouped processes safely.

## Status

This project is under active development.
Behavior and configuration may change until the first stable release.
It is not production-ready yet, and some commands may fail depending on environment or incomplete features.

## Features

- Switch workspaces and manage grouped process lifecycle (`wsx <workspace>`, `wsx up`, `wsx down`)
- Run commands in current workspace context (`wsx exec <cmd...>`)
- Layer environment resolution: OS -> dotenv -> envrc
- Inspect and follow logs by process/stream with detach support (`wsx logs`, `--no-follow`, `q` + Enter)
- Keep runtime state outside repositories (`~/.config/wsx`) with per-workspace instance retention

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

Detailed command usage is documented in:

- `docs/USAGE.md`

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
