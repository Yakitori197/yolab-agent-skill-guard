# Contributing

Thanks for considering a contribution. This project has a narrow, explicit
mission — an offline, read-only auditor for agent skill and instruction
files — and contributions are reviewed against that mission first.

## Ground rules

1. **Offline, always.** The scanner must never execute scanned content, fetch
   URLs, follow symlinks out of the root, read `.env*`/key/database files, or
   transmit anything. Changes that add network or execution behavior at scan
   time will be declined regardless of convenience.
2. **Deterministic, always.** Identical inputs must produce byte-identical
   JSON, SARIF, and HTML. No timestamps, no map-ordered output, no
   environment-dependent strings in reports.
3. **Honest findings.** Heuristic rules report *risk signals requiring
   review*; wording that declares content "malicious" is not acceptable.
4. **Rule IDs are API.** Once published, an ID (`ASG001`, …) is never renamed
   or reused. New rules take new IDs; retired rules are documented as retired.

## Development setup

- Go (see `go.mod` for the minimum version).
- No other runtime dependencies. `gopkg.in/yaml.v3` is the only third-party
  library (see `docs/dependencies.md`).

```bash
go build ./cmd/skillguard
go test ./...
```

Full local verification (format, vet, tests, race, coverage gate, build,
determinism checks, self-scan, action test):

```bash
sh scripts/verify.sh      # POSIX
```

```powershell
powershell -File scripts/verify.ps1   # Windows PowerShell 5.1+
```

## Tests

- Every rule change needs table-driven tests covering true positives, true
  negatives, and context handling (prose vs code fence vs cautionary text).
- Report changes update golden files: `go test ./internal/report/... -update`
  (review the diff — goldens are the contract).
- Aggregate statement coverage over `internal/` must stay at or above 90%
  (`go run ./tools/covercheck`). Do not exclude security modules to pass.
- Never commit credential-shaped literals. Synthetic secrets in tests are
  assembled at runtime (see `internal/rules/secrets_test.go`).

## Proposing a new rule

Open an issue using the *Rule proposal* template with: the risk it detects,
true/false-positive analysis, default severity with reasoning, and synthetic
examples. Rules with unavoidable false positives must be heuristics with
clearly reviewable messages.

## Commit and PR expectations

- Small, focused PRs with a clear risk statement.
- `docs/` is part of the deliverable: behavior changes update the matching
  documentation in the same PR.
- CI must be green; no skipped checks.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
