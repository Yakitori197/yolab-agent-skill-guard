# Text report

The default format, designed for terminals and CI logs.

## Layout

```text
skillguard dev — offline audit for agent skills and instruction files

root: <scan-root>
files scanned: 3 · skipped: 2 · suppressed: 1

SKILL.md
  12:9  critical  ASG001  Possible GitHub token detected (masked: ghp_******** (40 chars)).
        fix: Remove the credential and rotate it.
  20:5  medium  ASG008  Referenced local resource "steps/gone.md" does not exist in the package.
        fix: Create the referenced file, fix the path, or delete the stale reference.

skipped (never read):
  - .env — env-file-never-read

summary: critical 1 · high 0 · medium 1 · low 0 · info 0
result: FAIL — 1 finding(s) at or above fail-on threshold (high)
```

Findings are grouped by file in deterministic order (path → line → column →
rule ID). The `root:` line shows `<scan-root>` when you passed an absolute
path, and echoes a relative path exactly as you typed it, so terminal output
and CI logs never publish a local directory layout. `--show-paths` opts back
into the full path for local debugging.

## Hostile text

Paths and quoted fragments can contain anything a filesystem or a scanned
document allows. Before anything is written, every string that did not
originate in the renderer is escaped: control characters become `\n`, `\r`,
`\t` or `\xNN`; Unicode format characters (bidirectional overrides, zero-width
characters, the byte-order mark), the line and paragraph separators, and
malformed UTF-8 become `\uNNNN` or `\xNN`. Printable text of any script is
untouched, so a Traditional Chinese path or message reads exactly as it is on
disk. A filename containing a newline therefore cannot add a line that looks
like a finding, and cannot disturb the summary or result lines.

## Color

ANSI color is used only when **all** of these hold: format is `text`, output
goes to an interactive terminal (not a pipe, not `--output`), `--no-color`
was not given, and the `NO_COLOR` environment variable is empty. Severity
words are colorized; every colored token is individually reset.

## `--quiet`

Drops the banner, root line, remediation lines, and skipped list — keeping
findings, the summary, and the result line. Useful in CI where the SARIF/JSON
artifact carries the detail.

## Result line

- `PASS — no findings at or above fail-on threshold (high)`
- `FAIL — N finding(s) at or above fail-on threshold (high)`
- `PASS — fail-on is none (informational run)`

The exit code matches the result line: see [cli.md](cli.md#exit-codes).
