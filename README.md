# YoLab Agent Skill Guard

**Offline-first security, privacy, and compatibility auditor for AI agent
skills and instruction files.**

`skillguard` reads the files that steer AI coding agents — `SKILL.md`,
`AGENTS.md`, `CLAUDE.md`, `.claude/` skills and commands, `.cursor/rules/*.mdc`,
and plain Markdown instructions — and reports the risk signals hiding in
them: embedded credentials, destructive commands, download-and-execute steps,
prompt-injection phrasing, path escapes, broken references, over-broad tool
permissions, and unpinned supply-chain dependencies.

It is a single static binary that never executes what it scans, never touches
the network at runtime, never opens your `.env`, and produces byte-for-byte
deterministic reports built for CI.

[繁體中文說明 → README.zh-TW.md](README.zh-TW.md)

---

## The problem

Agent skills are programs written in prose. Agents read them with high trust
and act on them — yet they are shared, forked, and installed with less review
than any dependency in your lockfile. A skill package can:

- carry a **hardcoded token** into every fork and every model context window;
- instruct an agent to run **irreversible cleanup commands** (hard resets,
  force-cleans, table drops) as a casual step;
- **pipe a remote script into a shell**, handing code execution to whoever
  controls that host tomorrow;
- embed **prompt-injection phrasing** that tells the agent to abandon its
  prior rules or keep its actions hidden from the user;
- reference files **outside its own package** (`../../…`, absolute paths,
  percent-encoded traversal, symlinks) so reviewers never see what actually
  gets loaded;
- silently rot: **missing references**, invalid frontmatter, duplicate keys.

Nothing in the usual toolchain reviews these files. skillguard does.

## Features

- **12 detection rules** (`ASG001`–`ASG012`) plus a governance rule for
  expired suppressions (`ASG900`) — see the [rule summary](#rules) below.
- **Platform-aware**: classifies files as `claude`, `codex`, `cursor`, or
  `generic` and applies the right manifest expectations to each.
- **Severity you can trust**: a finding's severity comes from the rule alone.
  Nothing in the scanned file — prose vs code fence, blockquotes, warning
  words, or a prohibition of any shape — can lower it, remove a finding, or
  change the exit code. Exceptions live in the configuration, where they are
  visible, reasoned, and expiring.
- **Four report formats** — human `text`, versioned `json`, GitHub-ready
  `sarif` (2.1.0), and a self-contained accessible `html` page — all
  rendering the same findings in the same order.
- **Deterministic**: no timestamps, no map ordering, no absolute paths;
  two runs over the same input are byte-identical.
- **Config as policy**: `.skillguard.yml` with allow-listed domains and
  capabilities, per-rule severity overrides, and suppressions that require a
  reason and can expire.
- **CI-native**: exit codes 0/1/2, `--fail-on` thresholds, a summary file for
  shell consumption, and a Docker-based GitHub Action.

## Security model (short version)

The scanner treats every scanned file as hostile input and itself as a
read-only instrument:

| Promise | Enforcement |
|---|---|
| Never executes scanned content | No shell-out, no eval, no rendering — text analysis only |
| Never uses the network at runtime | No network code paths exist in the scanner |
| Never reads sensitive files | `.env*`, `*.pem/key/p12/pfx`, databases, archives are skipped **by name, unopened**, and reported as skipped |
| Never follows symlinks out of the root | Symlink targets are resolved and containment-checked by filesystem identity (`os.SameFile`), never by comparing lowercased paths |
| Never prints a secret | Suspected credentials are masked in every format; raw values never leave the matcher |
| Never drives your terminal | Filenames, messages, and the CLI's own diagnostics — including an unknown flag name echoed back by the `flag` package — are escaped before anything is written; `--no-color` output contains no ESC at all |
| Never claims malice | Heuristic findings are labeled risk signals requiring human review |

Details: [docs/security-model.md](docs/security-model.md) ·
[docs/threat-model.md](docs/threat-model.md) ·
[docs/privacy.md](docs/privacy.md)

## Quick start (30 seconds)

```bash
git clone https://github.com/Yakitori197/yolab-agent-skill-guard
cd yolab-agent-skill-guard
go build -o skillguard ./cmd/skillguard

./skillguard scan path/to/your/skills
```

Once a tagged release exists you will also be able to install with
`go install github.com/Yakitori197/yolab-agent-skill-guard/cmd/skillguard@<version>`.

## CLI

```bash
skillguard scan .                          # full scan, text report
skillguard scan pkg --format sarif --output report.sarif
skillguard scan pkg --format html  --output report.html
skillguard scan pkg --fail-on medium       # stricter CI gate
skillguard scan pkg --platform claude --platform cursor
skillguard validate pkg                    # structure/frontmatter/references only
skillguard rules                           # list the catalog
skillguard explain ASG004                  # one rule, in depth
skillguard init                            # write a .skillguard.yml template
skillguard version
```

Real output (excerpt from scanning the bundled
[`examples/risky-skill`](examples/risky-skill) fixture):

```text
SKILL.md
  1:1  high  ASG009  SKILL.md frontmatter is missing the required "description" field.
  4:1  critical  ASG006  allowed-tools grants a bare wildcard (*): every tool becomes available, which defeats least privilege.
  23:9  critical  ASG001  Possible connection string with embedded password detected (masked: Fak3******** (19 chars)). Treat this as a risk signal and rotate the credential if it is real.
  60:46  medium  ASG008  Referenced local resource "pipeline.md" does not exist in the package.

summary: critical 4 · high 7 · medium 7 · low 1 · info 0
result: FAIL — 11 finding(s) at or above fail-on threshold (high)
```

## GitHub Action

```yaml
jobs:
  skill-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      # Pin to a full commit SHA once the first release of this action exists:
      - uses: Yakitori197/yolab-agent-skill-guard@<pinned-commit-sha>
        with:
          path: .
          fail-on: high
          format: sarif
          output: skillguard-report.sarif
```

The action needs **no secrets**, sends **nothing anywhere**, and only scans
the checked-out workspace. The `output` may be a new file, but its immediate
parent directory must already exist: the action never creates directories and
never replaces an existing path. Outputs: `findings`, `critical`, `high`,
`medium`, `low`, `info`, `suppressed`, `report-path`. See
[docs/github-action.md](docs/github-action.md) for SARIF upload to Code
Scanning and threshold recipes.

## Supported files

| Platform | Files |
|---|---|
| `claude` | `SKILL.md` (+ everything in its package directory), `CLAUDE.md`, `.claude/skills/**`, `.claude/commands/*.md` |
| `codex` | `AGENTS.md` |
| `cursor` | `.cursor/rules/*.mdc`, any `*.mdc` |
| `generic` | any other `*.md` / `*.markdown` instruction file |

Relative resources referenced by these files are existence- and
containment-checked. Details: [docs/platform-support.md](docs/platform-support.md).

## Rules

| ID | Title | Default | Category |
|---|---|---|---|
| ASG001 | Hardcoded Secret | critical | secrets |
| ASG002 | Private Absolute Path | medium | privacy |
| ASG003 | Destructive Command | high | dangerous-commands |
| ASG004 | Remote Pipe Execution | critical | supply-chain |
| ASG005 | Undeclared Network Access | medium | network |
| ASG006 | Excessive Tool Permission | high | permissions |
| ASG007 | Path Escape | high | structure |
| ASG008 | Missing Reference | medium | structure |
| ASG009 | Invalid Manifest | medium | structure |
| ASG010 | Prompt Injection Signal | high | injection |
| ASG011 | Unpinned Remote Dependency | medium | supply-chain |
| ASG012 | Obfuscated Payload | high | obfuscation |
| ASG900 | Expired Suppression | info | governance |

Rule IDs are a stable API. Full rationale, examples, and remediation for each
rule: [docs/rules.md](docs/rules.md), or `skillguard explain <ID>`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan succeeded; nothing at or above the `--fail-on` threshold |
| `1` | Scan succeeded; findings at or above the threshold exist |
| `2` | Configuration, input, or runtime error (always fails closed) |

## Privacy promise

skillguard runs entirely on your machine. It transmits nothing, phones home
to nothing, and contains no telemetry or analytics of any kind. Files that
commonly hold secrets are never opened — they appear in the report only as
"present, skipped". Suspected secrets found in scanned text are masked in
every output format. The full policy, including what a report can and cannot
contain, is in [docs/privacy.md](docs/privacy.md).

## Report demos

Committed, deterministic reports generated from `examples/risky-skill`:

- HTML (self-contained, no JS, dark-mode aware):
  [docs/examples/risky-report.html](docs/examples/risky-report.html)
- SARIF 2.1.0: [docs/examples/risky-report.sarif](docs/examples/risky-report.sarif)
- JSON: [docs/examples/risky-report.json](docs/examples/risky-report.json)

Regenerate with `make demo` — the bytes must not change.

## Limitations

skillguard is a static, line-oriented analyzer with an explicit contract:

- Heuristic rules produce **risk signals**, not verdicts; both false
  positives and false negatives exist by design and are documented per rule.
- Patterns spanning multiple lines (a command split across continuation
  lines) can evade line-based matching.
- Only frontmatter YAML is parsed; embedded code blocks are matched as text,
  never interpreted.
- Encoded payloads are flagged by shape — never decoded.
- The full list lives in [docs/limitations.md](docs/limitations.md).

## Roadmap

Planned work (nothing here is implemented yet): see
[docs/roadmap.md](docs/roadmap.md).

## Contributing

Bug reports, rule proposals, and PRs are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues go through
[SECURITY.md](SECURITY.md), never public issues.

## License

[MIT](LICENSE) © 2026 Yakitori197 (YoLab)
