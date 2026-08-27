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
are resolved and containment-checked (case-folded on case-insensitive
filesystems) before reads; directory symlinks are never followed. Path
escapes become ASG007 findings — the target is never read.

*Pinned by:* `internal/pathsafe` exhaustive tables, discovery symlink tests,
ASG007 tests including percent-encoded and symlink escapes.

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
