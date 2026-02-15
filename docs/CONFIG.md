# wsx Config Reference (`~/.config/wsx/config.yaml`)

This document describes how to write `wsx` config and which values are supported by the current implementation.

## Config File Location

```text
~/.config/wsx/config.yaml
```

`wsx` reads config from this path.

## Load Rules

- If the file does not exist, `wsx` exits with an error.
- If YAML is invalid, `wsx` exits with an error.
- If `workspaces` is empty, `wsx` exits with an error.

## Overall Structure

```yaml
defaults:
  stop:
    grace_seconds: 5
  env:
    dotenv: [.env]
    envrc: false
  logs:
    lines: 200
    default: ""
    keep_instances: 20

workspaces:
  deva:
    path: /path/to/workspace
    stop:
      grace_seconds: 5
    env:
      dotenv: [.env, .env.local]
      envrc: true
    logs:
      lines: 200
      default: backend:err
      keep_instances: 20
    processes:
      - name: backend
        default_log: true
        default_stream: err
        cmd: ["go", "run", "./cmd/server"]
```

## `defaults`

Values under `defaults` are used when workspace-specific values are not provided.

### `defaults.stop.grace_seconds`

- Type: integer (`u64`)
- Default: `5`
- Meaning: graceful stop wait time in seconds before force stop

### `defaults.env.dotenv`

- Type: string array
- Default: `[".env"]`
- Meaning: dotenv files loaded from workspace root, in order
- Notes: missing files are skipped

### `defaults.env.envrc`

- Type: boolean
- Default: `false`
- Meaning: whether `.envrc` evaluation is enabled

### `defaults.logs.lines`

- Type: integer (`usize`)
- Default: `200`
- Meaning: initial tail line count for `wsx logs`

### `defaults.logs.default`

- Type: string
- Default: `""` (empty)
- Meaning: default log target

If empty, target is resolved from process settings (see resolution order below).

### `defaults.logs.keep_instances`

- Type: integer (`usize`)
- Default: `20`
- Meaning: how many old instances to keep per workspace
- Notes: `0` disables cleanup

## `workspaces.<name>`

### `path` (required)

- Type: string
- Required: yes
- Constraint: must exist and must be a directory

### `stop.grace_seconds` (optional)

- Type: integer (`u64`)
- Fallback: `defaults.stop.grace_seconds`

### `env.dotenv` (optional)

- Type: string array
- Fallback: `defaults.env.dotenv`

### `env.envrc` (optional)

- Type: boolean
- Fallback: `defaults.env.envrc`

### `logs.lines` (optional)

- Type: integer (`usize`)
- Fallback: `defaults.logs.lines`

### `logs.default` (optional)

- Type: string
- Fallback: `defaults.logs.default`
- If both are empty, target is auto-resolved from processes

### `logs.keep_instances` (optional)

- Type: integer (`usize`)
- Fallback: `defaults.logs.keep_instances`

### `processes` (required)

- Type: array
- Required: yes (must not be empty)

## `processes[]`

### `cmd` (required)

- Type: string array
- Required: yes (must not be empty)
- Execution: `cmd[0]` is executable, `cmd[1..]` are arguments

`wsx` does not automatically run through a shell.
For shell syntax, explicitly invoke your shell.

PowerShell example:

```yaml
cmd:
  - powershell
  - -NoProfile
  - -ExecutionPolicy
  - Bypass
  - -Command
  - aqua update-aqua; aqua update; aqua i -a
```

### `name` (optional)

- Type: string
- Fallback: filename part of `cmd[0]`
- Notes: duplicate names are suffixed (`-2`, `-3`, ...)

### `default_log` (optional)

- Type: boolean
- Default: `false`
- Meaning: mark this process as default log candidate

### `default_stream` (optional)

- Type: string
- Allowed: `combined`, `out`, `err`
- Default: `combined` (internally same as unset)

## Log Target Format

Used by both `logs.default` and `wsx logs [target]`:

- `<process>`
- `<process>:out`
- `<process>:err`

`<process>:combined` is not valid; use `<process>`.

## Default Log Target Resolution Order

1. `workspaces.<name>.logs.default`
2. `defaults.logs.default`
3. First process with `default_log: true`
4. First process entry

If the selected process has `default_stream`, it becomes `<name>:<stream>`.

## Environment Variable Application Order

1. OS environment
2. dotenv files (in configured order, last write wins)
3. `.envrc` (when enabled, final overwrite)

### `.envrc` execution

- Unix: `sh -lc "set -a; . ./.envrc; env"`
- Windows: `bash -lc "set -a; source ./.envrc; env"`

Notes:

- If `envrc: true` but `.envrc` is missing, it is skipped.
- On Windows, if `bash` is not found, `.envrc` is skipped with warning.
- If `.envrc` execution fails, workspace startup fails.

## Common Errors

- `config file not found`
- `invalid YAML`
- `workspaces is empty`
- `workspace <name> is not defined`
- `workspace path does not exist`
- `workspace path is not a directory`
- `workspace <name> has no processes`
- `process cmd must not be empty`
- `invalid default_stream`
- `invalid logs target`

## Minimal Example

```yaml
defaults:
  env:
    dotenv: [.env]
    envrc: false

workspaces:
  deva:
    path: /path/to/deva
    processes:
      - name: backend
        cmd: ["go", "run", "./cmd/server"]
```
