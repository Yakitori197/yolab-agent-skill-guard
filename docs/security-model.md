# Security model

Six promises, each enforced in code and pinned by tests. If any of them is
ever violated, that is a security vulnerability — report it via
[SECURITY.md](../SECURITY.md).

## 1. Scanned content is never executed

The scanner has no execution pathway: no `os/exec`, no eval, no template
rendering of scanned text, no URL fetching. Code blocks and commands are
pattern-matched as strings. Encoded blobs (ASG012) are flagged by shape and
explicitly **never decoded**.

*Pinned by:* absence of exec/network imports in scanner packages; ASG012
tests assert messages carry lengths, not decoded content.

## 2. No network at runtime

`skillguard scan` performs zero network I/O. There is nothing to configure
off — the code paths do not exist. Build-time dependency download is the
ordinary Go module flow, verified by `go.sum`.

*Pinned by:* code review + the action contract test running with no network
requirements; the privacy tests assert no content leaves via any report.

## 3. Sensitive files are never opened

Discovery classifies `.env` / `.env.*`, `*.pem/key/p12/pfx/ppk/jks/keystore`,
`*.db/sqlite/sqlite3/mdb`, and archive extensions **by name** and skips them
before any `open()`. For a symlink the same rule is applied to the resolved
target name, so `alias.md → .env` is refused rather than read. Content is then
read exactly once through a bounded reader capped at `max_file_size + 1` bytes,
with size and mode taken from the open handle; every byte actually read is
checked for NUL bytes, so a binary renamed to `.md` is skipped too — extension
alone is never trusted. The residual TOCTOU exposure is documented in
[file-discovery.md](file-discovery.md).

*Pinned by:* `internal/discovery` tests (including symlinks to `.env`, key
material and databases, bounded-read limits, and post-discovery symlink
escapes) and an app-level test asserting `.env` content never appears in any
output.

## 4. Nothing escapes the scan root

Every reference is resolved lexically (slash-normalized, percent-decoded,
cleaned) and checked against the root before any filesystem probe; symlinks
are resolved and containment-checked before reads; directory symlinks are
never followed. Path escapes become ASG007 findings — the target is never
read.

Containment itself never folds case. `runtime.GOOS` is not evidence about a
filesystem — macOS ships both case-insensitive and case-sensitive APFS, and
Windows supports per-directory case sensitivity — so a path is accepted only
when an exact canonical prefix proves it, or when walking its existing
ancestors finds one that `os.SameFile` says *is* the root directory. Where
identity cannot be obtained (an unreadable ancestor, a volume with no stable
file id), the check fails closed and the path is treated as outside.

*Pinned by:* `internal/pathsafe` exhaustive tables, `internal/discovery`
containment tests (including a case-only sibling directory), discovery symlink
tests, ASG007 tests including percent-encoded and symlink escapes.

## 5. Secrets never appear in output

Matches from secret patterns pass through `redact.Secret` (≤4-char prefix +
length) before entering a message; private-key findings carry no key
material at all; connection-string findings mask the password; home-path
findings redact the username segment. Fingerprints are one-way truncated
hashes.

*Pinned by:* per-pattern masking tests and end-to-end tests asserting the
synthetic secret string is absent from text/JSON/HTML outputs.

## 6. Findings describe risk, not guilt

Heuristic rules (`skillguard rules` marks them) phrase findings as risk signals
requiring human review.

Severity is fixed by the rule and is never influenced by the scanned text.
Earlier revisions lowered a finding when a prohibition appeared to govern the
same command; a conditional exception ("never run X **unless** the task
requires it; this task requires it") re-opened that door immediately, so the
inference was removed entirely. Prose vs fence, blockquotes, illustrative fence
languages, and warning words all leave severity, the existence of the finding,
and the exit code untouched.

Legitimate documentation is handled where it is visible and reviewable: a
reasoned, expiring suppression in the configuration — which is what this
repository does for its own rule catalog.
*Pinned by:* rule metadata tests, `internal/rules/negation_test.go` (conditional
and plain prohibitions alike keep the rule default severity), and end-to-end CLI
tests asserting a default `--fail-on high` run still exits 1.

## 7. Nothing the CLI prints can drive your terminal

The text report and the CLI's own diagnostics are the outputs a terminal
interprets, and much of what they print comes from outside the tool: a POSIX
filename may contain ESC, CR, LF and any byte but NUL and `/`, the root label
can be a path the user typed, finding messages quote scanned documents, and the
`flag` package echoes an unknown flag name verbatim — `skillguard scan
--<ESC>[2J` used to clear the screen from inside the standard library, where no
call-site `%q` could reach it.

Two boundaries close that. `internal/report/text` sanitizes every string it did
not author before adding its own ANSI. `internal/app/safeout.go` is the single
place the rest of the CLI writes human-readable text: a format string written
in this repository keeps its newlines and tabs, every *argument* is escaped
individually so an injected newline cannot forge a line, and each command's
`flag.FlagSet` writes into a buffer that is never forwarded — the parse error is
re-rendered as one sanitized line and the usage block is regenerated from this
tool's own flag definitions, so it stays readable. A test reads the package's
own source and fails if any file outside that boundary builds a flag set or
writes to a stream directly, so a command added later cannot quietly opt out.

Every such string passes through `internal/termsafe` before any ANSI is added. C0 and C1 controls (ESC, BEL, CR, LF, DEL), Unicode format
characters (bidirectional overrides and isolates, zero-width characters, the
byte-order mark), the line and paragraph separators, and malformed UTF-8 all
become visible, deterministic escapes; printable text of every script,
Traditional Chinese included, is returned byte-for-byte unchanged, so ordinary
reports did not change. With `--no-color` the output contains no ESC at all,
and in color mode the only escape sequences present are the six this renderer
emits. The two human-readable `stderr` lines that echo user text quote it with
`%q`.

The machine formats are deliberately excluded: JSON, SARIF and HTML escape at
their own layer, and terminal escapes would corrupt what consumers parse.

*Pinned by:* `internal/termsafe` unit tests,
`internal/report/text/hostile_test.go` (a hostile path cannot forge a finding,
summary, or result line), `internal/app/terminal_test.go` driving the real CLI,
and `internal/app/flagsafety_test.go`, which feeds an ANSI clear-screen as a
flag name to every command that parses flags — including `scan`'s second parse
pass for flags written after the path — and asserts both that nothing reaches
stderr raw and that the usage block is still readable.

## Hardening details

- RE2 regexes only (linear time); per-line scan cap 64 KiB; frontmatter parse
  cap 256 KiB; file cap 1 MiB default / 16 MiB ceiling.
- yaml.v3 runs behind a recover guard: a parser panic becomes a structured
  finding, not a crash.
- Errors and report headers never print a local absolute path: an absolute
  input is reduced to `<scan-root>` or `.../basename`, and `--show-paths` is
  the explicit opt-in for local debugging. They never carry file contents.
- Configuration must be exactly one YAML document; a second document after a
  `---` separator is a configuration error, not a silently ignored policy.
- Suppression scope is bounded: a wildcard `path` is refused unless pinned by
  a fingerprint, and patterns that could cover the whole supported file set
  are refused outright.
- Single-goroutine scanning: no unbounded concurrency, no shared mutable
  state, deterministic by construction (race detector runs in CI anyway).
- The HTML report ships a `default-src 'none'; style-src 'unsafe-inline'`
  CSP, inline CSS only, and no JavaScript at all.
