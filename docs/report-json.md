# JSON report — `skillguard-report/v1`

Machine-readable, versioned, and byte-for-byte deterministic. The normative
schema is [`schemas/report.schema.json`](../schemas/report.schema.json);
a committed example is
[`docs/examples/risky-report.json`](examples/risky-report.json).

## Shape

```json
{
  "schema": "skillguard-report/v1",
  "tool": { "name": "skillguard", "version": "dev" },
  "summary": {
    "files_scanned": 2,
    "files_skipped": 0,
    "suppressed": 0,
    "total_findings": 19,
    "critical": 4, "high": 7, "medium": 7, "low": 1, "info": 0
  },
  "findings": [
    {
      "rule": "ASG008",
      "severity": "medium",
      "path": "SKILL.md",
      "line": 60,
      "column": 46,
      "message": "Referenced local resource \"pipeline.md\" does not exist in the package.",
      "remediation": "Create the referenced file, fix the path, or delete the stale reference.",
      "fingerprint": "6ff8ec38ea0c9d25",
      "context": "prose",
      "platform": "claude"
    }
  ],
  "skipped": [
    { "path": ".env", "reason": "env-file-never-read" }
  ]
}
```

## Guarantees

- **Deterministic**: fixed field order (struct-defined, never map
  iteration), findings sorted path → line → column → rule ID, skipped sorted
  by path, empty collections as `[]` (never `null`), two-space indent,
  trailing newline. Identical inputs hash identically.
- **No timestamps** and **no absolute paths** — the scan root does not appear
  anywhere; `path` values are root-relative with forward slashes.
- **Secrets masked** — message text passes the same redaction as every other
  format. HTML-sensitive characters are `\uXXXX`-escaped by the encoder, so
  embedding the JSON in web contexts is safe by default.
- **Fingerprints** are 16-hex, computed from rule + path + matched content
  (not line/column), and are the values `suppressions[].fingerprint`
  consumes.

## Versioning

`schema` is bumped (v2, …) for breaking shape changes; additive fields may
appear within v1 and consumers should ignore unknown fields.
