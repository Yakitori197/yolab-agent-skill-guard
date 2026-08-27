# Threat model

## Assets

1. **The operator's machine and data** — filesystem contents outside the scan
   root, environment variables, credentials in `.env`/key files.
2. **The scan results** — reports may be shared (CI logs, SARIF uploads), so
   whatever enters a report effectively becomes public.
3. **The agent that will later read the scanned files** — the downstream
   asset skillguard exists to protect.

## Adversaries

| Adversary | Capability |
|---|---|
| Malicious skill author | Full control of scanned file contents |
| Compromised or trojaned skill repository | Ships subtly modified packages at scale |
| Curious-but-honest sharer | Publishes reports without reviewing them for leaks |
| Remote host referenced by a skill | Serves different content at install time than at review time |

Out of scope: an attacker with code execution on the operator's machine
already (skillguard cannot help there), and vulnerabilities in the agent
platforms themselves.

## Attack surfaces and mitigations

### 1. Scanned text attacks the scanner

- **Parser crashes / resource exhaustion.** Frontmatter parsing runs behind a
  recover guard (yaml.v3 has a history of panics on crafted input); file size
  is capped (`max_file_size`, hard ceiling 16 MiB); per-line pattern matching
  is capped at 64 KiB; all regexes run on Go's RE2 engine, which has linear
  time guarantees and no catastrophic backtracking. Fuzz tests
  (`internal/parser`) assert crash-freedom.
- **Report injection.** Findings quote fragments of hostile text. The HTML
  renderer escapes everything contextually (`html/template`) under a
  `default-src 'none'` CSP with zero JavaScript; JSON/SARIF strings are
  encoder-escaped. Adversarial fixtures assert `<script>` payloads and
  structure-breaking quotes are neutralized in every format.

### 2. Scanned text lures the scanner outside the root

- **Upward traversal** (`..`, mixed separators, percent-encoding) is resolved
  lexically first — escapes are *reported*, never followed.
- **Symlinks** are resolved with `EvalSymlinks` and containment-checked
  (case-folded on Windows/macOS) before any read; directory symlinks are
  never descended; cycles surface as unreadable, not hangs.
- **Absolute references** (drive letters, UNC, `~`, `file:`) are flagged and
  never resolved.

### 3. The scanner leaks operator data

- Sensitive files are excluded **by name before opening**: `.env`/`.env.*`,
  key material, databases, archives — and for a symlink the rule is applied to
  the resolved target name too, so `alias.md → .env` never gets read. They
  appear in reports only as `path — reason`.
- Content is read once through a bounded reader (`max_file_size + 1` bytes)
  with size and mode taken from the open handle, so an oversized or
  swapped-for-binary file cannot be loaded whole.
- Suspected secrets in scanned text are masked at the matcher boundary
  (`internal/redact`); raw values exist only transiently in memory.
- No report format carries the absolute scan root; the text header shows
  `<scan-root>` unless the user opts in with `--show-paths`, and error messages
  reduce absolute inputs to their last element. Home-directory paths found in
  *content* are reported with the username segment redacted.
- There is no telemetry, no crash reporting, no network I/O of any kind.

### 4. The verdict itself misleads

- Heuristic rules label findings as risk signals requiring review; wording
  never asserts malice.
- Severity is fixed by the rule. Author-controlled context — prose vs fence,
  blockquotes, fence languages, warning words, and prohibitions of any shape,
  including conditional ones ("never X unless …; this task requires it") —
  never lowers severity, removes a finding, or changes the exit code.
- Suppressions require a written reason, are scoped to a specific file (a
  wildcard needs a fingerprint, and repository-wide patterns are refused), and
  support expiry; expired ones surface as ASG900 findings.
- Configuration errors fail closed (exit 2) — a broken config can never
  silently narrow a scan, and a second YAML document can never carry a policy
  the reader does not see.

### 5. Supply chain of skillguard itself

- One third-party dependency (`gopkg.in/yaml.v3`), verified by `go.sum` and
  `go mod verify`; CI runs `govulncheck` (pinned version).
- CI actions are pinned to full commit SHAs; the action's Docker bases are
  pinned by digest.
- The GitHub Action needs no secrets and runs with `contents: read`.

## Residual risks

A tree rewritten *during* a scan retains a small TOCTOU window between the
stat and the open of each file, because Go offers no portable
`openat`/`O_NOFOLLOW`; scan a fixed checkout, as the Action does.

Line-based matching can be evaded by multi-line construction or novel
phrasing; encoded payloads are flagged by shape only (never decoded); and a
sufficiently creative instruction file can express harm in language no
pattern anticipates. skillguard reduces review burden — it does not replace
review. See [limitations.md](limitations.md).
