# CLI reference

```text
skillguard <command> [arguments] [flags]
```

Flags may appear before and/or after the path argument
(`skillguard scan pkg --format json` works).

## Commands

### `skillguard scan [path]`

Full structure, security, privacy, and compatibility scan. `path` defaults to
`.` and may be a directory or a single file (a single file is scanned with
its own directory as the root).

| Flag | Values | Default | Meaning |
|---|---|---|---|
| `--format` | `text` `json` `sarif` `html` | `text` | Report format |
| `--output FILE` | path | stdout | Write the report to a file (a confirmation note goes to stderr) |
| `--config FILE` | path | auto | Configuration file; default is `.skillguard.yml` at the scan root, else built-in defaults |
| `--fail-on` | `critical` `high` `medium` `low` `info` `none` | config (`high`) | Threshold for exit code 1 |
| `--platform` | `codex` `claude` `cursor` `generic` (repeatable) | all | Restrict scanned platforms (overrides config) |
| `--summary FILE` | path | — | Also write `key=value` counters (`findings`, per-severity, `suppressed`, `files-scanned`) for shells/CI |
| `--no-clobber` | — | off | Refuse to write the report over an existing file (`O_EXCL`). The GitHub Action always sets this; the plain CLI overwrites by default so re-running a scan into the same report file works. Neither mode creates missing parent directories |
| `--show-paths` | — | off | Show the full local scan root in text output; off by default so shared output carries no local directory layout |
| `--no-color` | — | off | Disable ANSI colors |
| `--quiet` | — | off | Text format: findings and result only |

Color is applied only when writing text to an interactive terminal, and is
disabled by `--no-color`, by a non-empty `NO_COLOR` environment variable, or
when `--output` is used.

### `skillguard validate [path]`

Same engine, structural rules only (ASG007 Path Escape, ASG008 Missing
Reference, ASG009 Invalid Manifest). Accepts the same flags as `scan`.
Use it as a fast pre-publish package check.

### `skillguard rules`

Prints the catalog: ID, default severity, category, heuristic flag, title,
summary. Deterministic order (by ID).

### `skillguard explain RULE_ID`

Prints one rule in full: rationale, remediation, safe and risky synthetic
examples, supported contexts. IDs are case-insensitive. Unknown IDs exit 2.

### `skillguard init`

Writes a commented `.skillguard.yml` template into the current directory.
If the file already exists the command **refuses to overwrite it** and exits
2. The generated template is itself a valid configuration.


### `skillguard action-paths --workspace DIR --path P [--config C] --output O`

CI helper used by the bundled GitHub Action. It validates wrapper-supplied
path inputs — rejecting absolute, drive-letter, UNC, `~`, `..`, dash-leading
and control-character values, resolving symlinks, and proving containment in
the workspace — then prints `path=`, `config=`, `output=`, and `report-path=`
lines for the caller to consume. Exit code 2 on any violation.

The `--output` value may be a new file, but its **immediate parent directory
must already exist**: the action never creates directories and never replaces
an existing path. The helper deliberately does not walk up to the nearest
existing ancestor, so it can never accept a destination that the subsequent
`O_EXCL` write would fail on.

Keeping this in Go (rather than in the entrypoint shell) is deliberate: the
rules are unit-tested in `internal/actionpath` and the shell script performs
no containment reasoning of its own. See
[github-action.md](github-action.md).

### `skillguard version`

Prints version, commit, build date, and the Go runtime version. Local builds
report `dev` / `unknown` — values are injected only by real release builds
and never fabricated.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan succeeded; no findings at or above the fail-on threshold |
| `1` | Scan succeeded; at least one finding at or above the threshold |
| `2` | Configuration, input, I/O, or runtime error — the scan fails closed |

`--fail-on none` makes findings informational (exit 0 unless a real error
occurs).

## Recipes

```bash
# CI gate at medium, SARIF for code scanning
skillguard scan . --fail-on medium --format sarif --output skillguard.sarif

# Machine-readable audit of one skill package
skillguard scan .claude/skills/deploy --format json | jq '.summary'

# Pre-publish structural check
skillguard validate my-skill/

# Scan only Cursor rules in a monorepo
skillguard scan . --platform cursor
```
