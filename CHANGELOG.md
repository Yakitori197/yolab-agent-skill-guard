# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Scanned content can no longer influence a finding at all. The previous
  release note described a narrowed prohibition guard; a conditional exception
  ("Never run git reset --hard **unless** the task requires it; this task
  requires it.") re-opened it, so the inference was removed outright. ASG003,
  ASG004 and ASG010 now always report their rule default severity, and an
  ASG006 blanket-permission request is reported even when the same line carries
  a disclaimer. Legitimate documentation is handled with reasoned, expiring
  suppressions instead.
- The GitHub Action never replaces an existing path. The extension-based
  allow-list is gone: any existing output — package.json, LICENSE, Makefile,
  Dockerfile, an extensionless file, a previous report, a directory, a symlink,
  or a hard link — is refused with exit code 2. The refusal is enforced again
  at the write itself via `O_WRONLY|O_CREATE|O_EXCL` (`--no-clobber`, which the
  action always sets), so a file appearing between validation and writing is
  still not truncated.
- The GitHub Action output contract now matches what the write layer can
  actually do: the destination may be a new file, but its **immediate parent
  directory must already exist**. Validation no longer walks up to the nearest
  existing ancestor, so `new-dir/report.sarif` is refused with exit code 2
  instead of being accepted and then failing at the `O_EXCL` open — and no
  directory is created either way. The parent is still resolved through
  symlinks and containment-checked against the workspace.
- The GitHub Action validates every path input through a unit-tested Go helper
  (`skillguard action-paths`): absolute, drive-letter, UNC, `~`, `..`,
  dash-leading and control-character values are rejected, symlinks are
  resolved and containment-checked against `GITHUB_WORKSPACE`, the output
  destination is verified through its immediate parent directory. The value
  written to `GITHUB_OUTPUT` is a validated single line.
- File reading is unified and bounded: `Lstat` first, symlinks resolved and
  re-checked for containment, the never-read name rules applied to the
  resolved target too (`alias.md → .env` is refused), one open per file with
  size and mode from the open handle, a reader capped at `max_file_size + 1`
  bytes, and binary detection over every byte actually read. Single-file scans
  take the same path as walked files.
- Configuration must be exactly one YAML document; a second document after a
  `---` separator is now a configuration error instead of being ignored.
- Suppression scope is bounded: a wildcard `path` requires a fingerprint, and
  patterns that could cover the whole supported file set (`**`, `*`,
  `**/*.md`, `docs/**`, …) are rejected.
- No report format or error message prints a local absolute path any more: the
  text header shows `<scan-root>`, absolute inputs in errors are reduced to
  their last element, and `--show-paths` is an explicit opt-in.

### Added

- `skillguard` CLI with `scan`, `validate`, `rules`, `explain`, `init`, and
  `version` commands.
- Rule catalog ASG001–ASG012 covering hardcoded secrets, private absolute
  paths, destructive commands, remote pipe execution, undeclared network
  access, excessive tool permissions, path escapes, missing references,
  invalid manifests, prompt-injection signals, unpinned remote dependencies,
  and obfuscated payloads — plus the ASG900 governance rule for expired
  suppressions.
- Platform-aware scanning for Claude skills (`SKILL.md`, `.claude/`),
  Codex (`AGENTS.md`), Cursor (`.mdc` rules), and generic Markdown
  instruction files.
- Deterministic text, JSON, SARIF 2.1.0, and self-contained HTML reports.
- `.skillguard.yml` configuration (schema version 1) with include/exclude,
  allowed domains and capabilities, severity overrides, and expiring,
  reason-required suppressions.
- Offline-first privacy model: sensitive files (`.env*`, key material,
  databases, archives) are reported as skipped without ever being read;
  binaries are detected by content sniffing; symlinks never escape the root;
  suspected secrets are always masked.
- Docker-based GitHub Action with SARIF output for Code Scanning.
- CI with race detector, cross-platform builds, coverage gate, dependency
  vulnerability checks, self-scan, and action smoke tests.
