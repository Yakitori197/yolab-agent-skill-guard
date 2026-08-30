# Privacy

## Summary

Everything happens on your machine. skillguard sends nothing, stores nothing
outside the report files you ask for, and is engineered so that even the
reports you *share* cannot leak what the scanner refused to read.

## What is never read

| Class | Match | Behavior |
|---|---|---|
| Environment files | `.env`, `.env.*` (any case) | Skipped unopened; listed as `env-file-never-read` |
| Key material | `*.pem .key .p12 .pfx .ppk .jks .keystore` | Skipped unopened; `key-material-never-read` |
| Databases | `*.db .sqlite .sqlite3 .mdb` | Skipped unopened; `database-file-never-read` |
| Archives | `*.zip .tar .gz .tgz .bz2 .xz .7z .rar .jar .war` | Skipped unopened; `archive-never-read` |
| Binary content | NUL byte anywhere in the bounded read | Skipped after reading; `binary-content` |
| Symlink to a protected file | e.g. `alias.md` pointing at `.env` | Skipped by the resolved name, with the protected reason reported |
| Oversized files | larger than `max_file_size` | Skipped by size stat; `exceeds-max-file-size` |
| Default directories | `.git node_modules vendor dist build coverage .next test-results playwright-report` | Never entered |

These exclusions are hard-coded and cannot be disabled by configuration —
`include` patterns cannot re-add them.

## What a report can contain

- Root-relative paths (forward slashes), line/column numbers, rule IDs,
  severities, messages, remediation text, fingerprints, skip reasons.
- Masked fragments of suspected secrets: at most a 4-character prefix plus a
  length, e.g. `ghp_******** (40 chars)`.
- Home-directory paths found in scanned *content*, with the username segment
  replaced by `<redacted-user>`.

## What a report can never contain

- The contents (or any metadata beyond name and skip reason) of skipped
  files.
- An unmasked suspected credential, in any format.
- The absolute path of the scan root, unless you ask for it. The
  machine-readable formats (JSON, SARIF, HTML) never carry it under any flag.
  The text header shows `<scan-root>` for an absolute input and echoes a
  relative input exactly as you typed it; `--show-paths` is the one explicit
  opt-in that prints the real root, and it affects text output only.
- A local absolute path inside an error message: an absolute input is reduced
  to its last element (`.../no-such.yml`) before being quoted back.
- Timestamps, hostnames, usernames of the operator, environment variables,
  or any identifier of the scanning machine.

## Telemetry

There is none. No usage analytics, no crash reporting, no update checks, no
network sockets. This is a design invariant, not a setting — see
[ADR-0002](decisions/0002-offline-security-model.md).

## The GitHub Action

The action runs the same binary inside the runner. It requires no secrets,
declares `contents: read`, scans only the checked-out workspace, and writes
its report into that workspace. Whether the report is uploaded anywhere
(e.g., Code Scanning) is entirely your workflow's decision.
