# Dependencies

Policy: standard library first; every third-party module needs a purpose no
stdlib feature covers, a permissive license, and an entry here. Anything
unexplained in `go.mod` is a review failure.

## Runtime dependencies

| Module | Version | License | Purpose | Why not stdlib |
|---|---|---|---|---|
| `gopkg.in/yaml.v3` | v3.0.1 | MIT and Apache-2.0 (per its LICENSE: project code MIT-licensed with portions of the libyaml port under Apache-2.0) | Parsing YAML frontmatter and `.skillguard.yml`, with per-node line positions (`yaml.Node`) used for precise finding locations, duplicate-key detection, and strict unknown-field rejection | The standard library has no YAML support; hand-rolling a YAML subset would be a larger correctness risk than the dependency |

Defensive note: `yaml.Unmarshal`/`Decode` run behind recover guards
(`internal/parser`, `internal/config`) because the parser has historically
panicked on crafted inputs — a scanner of untrusted text must not crash.

## Test-only entries in `go.sum`

`gopkg.in/check.v1` appears in `go.sum` as yaml.v3's test dependency; it is
not built into skillguard.

## Toolchain

- Go — minimum version in `go.mod` (`1.26`), chosen as the older of the two
  Go release lines still supported upstream at the time of writing
  ([ADR-0001](decisions/0001-language-and-runtime.md)).
- CI extras, pinned: `golang.org/x/vuln/cmd/govulncheck@v1.7.0`
  (vulnerability scanning); GitHub actions pinned by full commit SHA; Docker
  base images pinned by digest.

## Verification

```bash
go mod verify        # checksums of everything in the module cache
go list -m all       # the full (two-line) module graph
```

CI runs `go mod verify` and `govulncheck ./...` on every push.
