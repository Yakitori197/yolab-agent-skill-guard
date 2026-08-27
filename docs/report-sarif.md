# SARIF report

`--format sarif` emits SARIF 2.1.0 designed for GitHub Code Scanning
ingestion. A committed example:
[`docs/examples/risky-report.sarif`](examples/risky-report.sarif).

## Mapping

| skillguard | SARIF |
|---|---|
| Rule catalog (all 13 rules, always) | `runs[0].tool.driver.rules[]`, ordered by ID; results carry matching `ruleIndex` |
| Severity critical / high | `level: "error"` |
| Severity medium | `level: "warning"` |
| Severity low / info | `level: "note"` |
| Severity (numeric) | rule `properties."security-severity"`: 9.5 / 8.0 / 5.5 / 3.0 / 0.0 — matching GitHub's critical ≥ 9, high 7–8.9, medium 4–6.9, low < 4 buckets |
| Finding position | `physicalLocation.region.startLine/startColumn` (1-based; `columnKind: unicodeCodePoints`) |
| Path | `artifactLocation.uri`, root-relative, forward slashes, never absolute |
| Fingerprint | `partialFingerprints["skillguard/v1"]` |
| Context, platform | `result.properties` |
| Rule docs | `helpUri` → the rule's anchor in [rules.md](rules.md) |

Heuristic rules append a "risk signals requiring human review" note to their
SARIF help text.

## Determinism and privacy

Fixed struct field order, rules and results in stable order, no timestamps,
no invocation block, no absolute local paths, masked secrets — identical
inputs produce byte-identical SARIF. Golden tests pin the exact bytes.

## Uploading to Code Scanning

```yaml
- uses: Yakitori197/yolab-agent-skill-guard@<pinned-commit-sha>
  with:
    path: .
    format: sarif
    output: skillguard-report.sarif
    fail-on: none          # let Code Scanning triage instead of failing CI
- uses: github/codeql-action/upload-sarif@42947a340483f03ba47bb1a039b2c519aab3df85 # v3.37.8
  with:
    sarif_file: skillguard-report.sarif
```

(The upload step needs `security-events: write` permission. Use
`fail-on: high` instead of `none` when you want the job itself to gate.)
