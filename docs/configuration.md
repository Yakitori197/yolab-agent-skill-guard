# Configuration — `.skillguard.yml`

skillguard looks for `.skillguard.yml` at the scan root, unless `--config`
names a file explicitly. Without either, built-in defaults apply. A JSON
Schema is published at
[`schemas/skillguard-config.schema.json`](../schemas/skillguard-config.schema.json).

**Fail-closed contract:** any configuration problem — unknown field,
duplicate key, unknown rule ID, invalid glob, empty suppression reason,
over-broad suppression scope, disable-everything attempts, or a second YAML
document after a `---` separator — aborts the run with exit code 2. A broken
config can never silently scan less than you asked for, and a policy the
reader cannot see can never take effect.

## Minimal example

```yaml
version: 1
```

## Full example

```yaml
version: 1                      # required; this build supports exactly 1
fail_on: high                   # critical|high|medium|low|info|none

platforms:                      # omit for all four
  - claude
  - cursor

include:                        # relative globs, forward slashes, ** ok
  - "skills/**/*.md"
exclude:
  - "drafts/**"

max_file_size: 1048576          # bytes; 1 KiB ≤ value ≤ 16 MiB

allowed_domains:                # ASG005 allow-list
  - "api.partner.example.com"   # exact host + subdomains
  - "*.cdn.example.com"         # wildcard form

allowed_capabilities:           # frontmatter capabilities (ASG005/ASG006)
  - network

disabled_rules:                 # disabling every detection rule is rejected
  - ASG011

severity_overrides:
  ASG002: low

suppressions:
  - rule: ASG003
    path: "docs/dangerous-examples.md"
    reason: "Documented destructive-command examples, fenced and annotated."
    expires: "2027-01-01"       # optional; inclusive last valid day
  - rule: ASG008
    fingerprint: "0123456789abcdef"   # from a JSON/SARIF report
    reason: "Reference intentionally created at runtime by the installer."
```

## Field reference

| Field | Type | Notes |
|---|---|---|
| `version` | int | Required. Only `1` is accepted. |
| `fail_on` | enum | Default `high`. `none` disables the findings exit code. |
| `platforms` | list | Must be non-empty when present; values `codex` `claude` `cursor` `generic`. |
| `include` / `exclude` | globs | Matched against root-relative slash paths. `*` (segment), `?` (char), `**` (across segments). Backslashes, absolute paths, and `..` are rejected. Include cannot re-add hard-coded sensitive exclusions. |
| `max_file_size` | bytes | Files larger are skipped and reported. |
| `allowed_domains` | list | Case-insensitive; entry covers itself and subdomains; `*.host` covers subdomains only. |
| `allowed_capabilities` | list | Case-insensitive capability names skills may declare. |
| `disabled_rules` | rule IDs | Unknown IDs are errors. ASG900 (governance) cannot be disabled. Disabling all detection rules is rejected. |
| `severity_overrides` | map | Rule ID → severity. Applied before suppression matching. |
| `suppressions` | list | See below. |

## Suppressions

Each suppression must name a `rule`, carry a non-empty `reason`, and be scoped
by `path` and/or `fingerprint` (the 16-hex value printed in JSON and SARIF
reports). When both are present, both must match.

- **Reasons are mandatory** — a suppression without a justification is a
  config error.
- **A path names one file.** Wildcards (`*`, `?`) are rejected in `path`
  unless the entry also carries a `fingerprint`, which pins the exception to a
  single known finding. Even then, patterns that could cover the whole
  supported file set are refused: `**`, `*`, `**/*.md`, `**/*.md*`, `docs/**`,
  `docs/*`, and any pattern whose file name is entirely wildcarded.
- **Expiry is inclusive** — the suppression works through `expires` day and
  stops the day after. Expired suppressions surface as
  [ASG900](rules.md#asg900) findings pointing at the config file, so lapsed
  exceptions get re-reviewed instead of living forever.
- Suppressed findings are counted (`suppressed` in every report summary) but
  not listed.

Fingerprints are computed from rule + path + matched content (not line
numbers), so ordinary edits elsewhere in the file do not break them.

## Precedence

1. `--config FILE` (flag) over auto-discovered `.skillguard.yml` over
   built-in defaults.
2. `--fail-on` flag over `fail_on` in config.
3. `--platform` flags replace the config `platforms` list entirely.
