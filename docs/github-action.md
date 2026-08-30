# GitHub Action

The repository root's [`action.yml`](../action.yml) defines a Docker-based
action: the container builds `skillguard` from this repository's own source
(both base images pinned by digest in
[`Dockerfile.action`](../Dockerfile.action)), so consumers need no Go
toolchain and no prebuilt binary trust.

## Contract

- Scans **only the checked-out workspace**. Every path input is validated by
  `skillguard action-paths` (unit-tested in `internal/actionpath`) before the
  scanner runs: absolute, drive-letter, UNC and `~` values, any `..` segment,
  dash-leading values, and NUL/CR/LF/other control characters are rejected;
  symlinks are resolved and the result must still live inside
  `GITHUB_WORKSPACE`.
- The `output` destination is **never allowed to replace anything**. If any
  path already exists there — a source file, a previous report, a directory, a
  symlink, or a hard link — the run is refused with exit code 2. There is no
  allow-list of "safe to overwrite" names, because such a list can never be
  complete.
- The output **may be a new file, but its immediate parent directory must
  already exist**; the action never creates directories and never replaces an
  existing path. A value such as `new-dir/report.sarif` is refused with exit
  code 2 rather than accepted and then failed at the write, and nothing is
  created on disk. Prepare the directory in an earlier workflow step
  (`mkdir -p reports`) if you want the report somewhere new. The parent is
  resolved through symlinks and containment-checked, so a symlinked directory
  cannot redirect the report outside the workspace.
- The refusal is enforced twice: once during validation, and again at the write
  itself, which opens the report with `O_WRONLY|O_CREATE|O_EXCL`. A file that
  appears between the two is still not truncated.
- The `key=value` lines the entrypoint parses are a **machine protocol, not
  human text**: they are written verbatim and never escaped, because each value
  is a filename the action then writes to. Escaping one would hand the caller a
  different path. Instead every value is validated first — a C0, DEL or C1
  control anywhere in the workspace, path, config or output is refused with
  exit code 2 and nothing is printed — so a legal name containing, say, a
  bidirectional override survives byte for byte, while a name that would break
  the line-based protocol never reaches it.
- The entrypoint emits every value with `printf` and a literal format string,
  never `echo`. The action image is Alpine, whose `/bin/sh` is BusyBox ash, and
  Debian runners provide dash; both ship an XSI `echo` that interprets
  backslash escapes *inside its argument*. A backslash is legal in a POSIX
  filename, so `a\tb.json` would have been written with a real tab,
  `a\nb.json` would have split into two lines and forged an extra
  `GITHUB_OUTPUT` entry, and `a\cb.json` would have truncated the line.
- The value written to `GITHUB_OUTPUT` as `report-path` is that validated,
  single-line, workspace-relative path, unmodified, so no output injection is
  possible and the report is written where the caller asked. The entrypoint
  deliberately does not echo it to the runner log: escaping it for display
  would print something that is not the real path, and printing it raw would
  hand the log whatever the filename contains.
- Needs **no secrets** and no permissions beyond `contents: read`.
- Transmits nothing; the report is written into the workspace.
- Inputs reach the entrypoint as argv, never interpolated into a shell string;
  enumerated inputs are validated against fixed lists; the scanner invocation
  terminates flag parsing with `--`; there is no `eval` anywhere.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory (or file) to scan, workspace-relative |
| `config` | auto | `.skillguard.yml` path; empty auto-discovers at the scan root |
| `fail-on` | `high` | `critical` `high` `medium` `low` `info` `none` |
| `format` | `sarif` | `text` `json` `sarif` `html` |
| `output` | `skillguard-report.sarif` | Report file path (workspace-relative). Must not already exist, and its immediate parent directory must already exist — the action creates no directories and replaces no existing path |

## Outputs

`findings`, `critical`, `high`, `medium`, `low`, `info`, `suppressed`,
`report-path`. Outputs are populated even when the scan fails the job
(exit 1), so downstream steps can report counts.

## Usage

```yaml
name: skill-audit
on: [push, pull_request]

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      # Pin to a full commit SHA once the first release exists:
      - id: guard
        uses: Yakitori197/yolab-agent-skill-guard@<pinned-commit-sha>
        with:
          path: .
          fail-on: high
          format: sarif
          output: skillguard-report.sarif
      - name: Counts
        if: always()
        run: echo "findings=${{ steps.guard.outputs.findings }} critical=${{ steps.guard.outputs.critical }}"
```

SARIF upload to Code Scanning: see [report-sarif.md](report-sarif.md).

## Failure semantics

| Scan outcome | Job |
|---|---|
| No findings ≥ `fail-on` | step succeeds (exit 0) |
| Findings ≥ `fail-on` | step fails (exit 1), outputs still populated |
| Config/input error | step fails (exit 2) — fail closed |

## Testing the action

- `sh scripts/test-action.sh` runs the real entrypoint against a throw-away
  workspace with a locally built binary — no Docker, no network — asserting the
  happy paths and every hostile-input rejection: traversal, absolute,
  drive-letter, UNC, dash-leading, CR/LF, symlink escapes for path/config/
  output, and the unconditional output no-clobber (package.json, LICENSE,
  Makefile, Dockerfile, extensionless files, previous reports, hard links),
  with checksums proving every refused run left those files byte-identical.
  It also proves a legal but awkward filename survives end to end: a U+202E
  output lands on exactly the requested path, and an output containing a
  backslash (`a\tb.json`, `a\nb.json`, `a\cb.json`) reaches
  `GITHUB_OUTPUT` byte for byte without the shell reinterpreting it or forging
  an extra line. Where the OS cannot express a case — real links, or a
  backslash in a filename on Windows — it is reported as skipped; Linux CI sets
  `SKILLGUARD_REQUIRE_SYMLINKS=1`, `SKILLGUARD_REQUIRE_HARDLINKS=1` and
  `SKILLGUARD_REQUIRE_BACKSLASH_PATHS=1`, which turn those skips into failures.
- CI additionally runs the true Docker path (`uses: ./`) on both fixtures.
- The action is not published to the Marketplace and has no releases yet;
  consume it by commit SHA once the repository is public.
