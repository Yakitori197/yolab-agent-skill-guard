# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Containment no longer folds case, and no longer infers filesystem behavior
  from `runtime.GOOS`. `CaseInsensitiveFS()` (`GOOS == windows || darwin`) plus
  a lowercased path comparison used to accept any path whose *lowercased*
  string sat under the lowercased root, so on a case-sensitive APFS volume or
  a Windows directory with per-directory case sensitivity enabled, `…/PKG/x`
  was authorized against the root `…/pkg` even though the two are different
  directories. Containment is now settled either by a byte-exact canonical
  prefix or by filesystem identity: the candidate's existing ancestors are
  walked and `os.SameFile` decides whether one of them *is* the root. Where
  identity cannot be obtained — an unreadable ancestor, a volume with no
  stable file id — the check fails closed. A path is never authorized because
  two strings match after lowercasing. The flaw did not even need a
  case-sensitive filesystem to reach: `strings.ToLower` folds U+212A KELVIN
  SIGN to ASCII `k`, while every mainstream filesystem keeps the two names
  apart, so a directory named U+212A was authorized against the root `k` on
  NTFS today. That exact case is now a regression test.
- The action entrypoint emits with `printf`, never `echo`. A backslash is a
  legal character in a POSIX filename, and skillguard rightly accepts one — it
  is not a control character, so the machine-output validator passes it — but
  the XSI `echo` that `/bin/sh` provides on Alpine (BusyBox ash, the action's
  own image) and on Debian runners (dash) interprets backslash escapes *inside
  its argument*. An output named `a\tb.json` was reported with a real tab,
  `a\nb.json` split into two lines and forged an extra `GITHUB_OUTPUT`
  entry, and `a\cb.json` truncated the line at the `a` — so the action's
  `report-path` output no longer named the file the report was actually written
  to. Every emission in `scripts/action-entrypoint.sh` now uses `printf` with a
  literal format string and the value as a `%s` argument, which copies it
  verbatim on every shell and also makes a `%` in the path data rather than
  syntax. A portable Go guard reads the script and fails on any `echo`, and the
  contract test drives real backslash filenames end to end where the filesystem
  can express them.
- The GitHub Action's `key=value` output is a machine protocol again, not
  human text. It had been routed through the terminal sanitizer, so a path the
  validator had just *accepted* came back rewritten: an output named
  `report<U+202E>gnp.json` came out with that override replaced by its
  six-character backslash-u escape, so the action would have written its report
  to a different file than the caller asked for, silently. `action-paths` now
  writes through a separate `machineWriter` that never escapes; instead every
  value is validated first, and a C0, DEL or C1 control anywhere in it is
  refused with exit code 2 and nothing printed. The workspace path is validated
  too, not only the relative inputs — on Unix a directory name may legally
  contain a newline. The
  entrypoint no longer echoes the report path to the runner log, because
  escaping it for display would print something that is not the real path.
- `FoldsCase` is no longer fooled by hard links. Two entries whose names differ
  only by case can point at one inode on a case-sensitive filesystem, and
  `os.SameFile` then answers "same file" for a directory that is plainly
  holding both spellings apart. The exact spellings a directory contains are
  now checked first, by byte equality and never `strings.EqualFold`, so
  `Skill.md` alongside `sKILL.MD` decides the question before identity is
  consulted.
- `flipCase` no longer claims a name changed when the case mapping left it
  alone. `unicode.IsLower` reporting true does not mean the simple uppercase
  mapping moves the rune: U+00DF maps to itself, and U+00AA does the same on
  toolchains that classify it as lowercase. The old code reported "changed",
  `FoldsCase` then stat'ed one identical path twice, and `os.SameFile`
  trivially agreed — turning a case-sensitive directory into a case-folding
  verdict. The flag now rises only when a mapping actually moves a rune, and
  the whole string is compared as a final check.
- Case folding survives only where it is a reporting choice (package
  containment for ASG007, missing-reference de-duplication), and the flag is
  now observed rather than assumed from the operating system. The probe is
  read-only and asks the right question: it lists the scan root and checks
  whether the root resolves one of *its own entries* under a differently-cased
  spelling, using `os.SameFile`. An earlier revision flipped the root's own
  name and looked it up in the root's parent, which measures how the parent
  resolves its children — a different question, and one Windows answers
  differently, because case sensitivity there is a per-directory attribute.
  Any inconclusive outcome — an unreadable directory, no entry carrying a
  cased letter, an empty directory — answers "do not fold", the stricter
  option. The answer describes the scan root itself; a nested directory may
  differ, and nothing depends on it beyond reporting.
- The text report can no longer be used to drive a terminal. POSIX filenames
  may contain ESC, CR, LF and any other byte but NUL and `/`, and the renderer
  printed the root label, finding paths, messages, remediations and skipped
  paths verbatim — so a crafted filename could clear the screen, set the
  window title through an OSC sequence, reorder text with bidi overrides, or
  forge a finding, summary or result line. Every string that does not
  originate in the renderer now passes through the new `internal/termsafe`
  before the renderer's own ANSI is added: C0/C1 controls, Unicode format
  characters, the line and paragraph separators, and malformed UTF-8 become
  visible deterministic escapes, while printable text of any script —
  Traditional Chinese included — is byte-for-byte unchanged. `--no-color`
  output now contains no ESC at all.
- The CLI's own diagnostics are covered too, not just the report. Go's `flag`
  package prints `flag provided but not defined: -<name>` with the name copied
  from argv, so `skillguard scan --<ESC>[2J` cleared the terminal from inside
  the standard library, where no call-site `%q` could reach. Package app now
  writes every human-readable byte through one boundary
  (`internal/app/safeout.go`): a format string written here keeps its layout,
  each argument is escaped on its own so an injected newline cannot forge a
  line, and every command's flag set writes into a buffer that is never
  forwarded — the parse error is re-rendered as a single sanitized line and the
  usage block is regenerated from this tool's own flag definitions, so it stays
  readable. A test reads the package's source and fails if any file outside the
  boundary builds a flag set or writes to a stream directly.
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

### Changed

- CI pins `actions/checkout` at `3d3c42e5aac5ba805825da76410c181273ba90b1`
  (v7.0.1) and `actions/setup-go` at
  `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` (v7.0.0). The previous pins
  (checkout v4.4.0, setup-go v5.6.0) target the Node 20 runtime that GitHub
  now forces onto Node 24. Both are still pinned by full commit SHA with the
  version in a comment; the `checkout` examples in the READMEs and
  [docs/github-action.md](docs/github-action.md) were updated to match. No
  workflow permission changed: every job still runs with `contents: read`.

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
