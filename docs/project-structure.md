# Project structure

```text
.
├── cmd/skillguard/          # main() shim; all logic is in internal/
├── internal/
│   ├── actionpath/          # CI-wrapper path validation (GitHub Action)
│   ├── app/                 # CLI commands, scan engine, exit codes
│   ├── config/              # .skillguard.yml parsing and validation
│   ├── discovery/           # file walking + privacy gate
│   ├── model/               # shared types (Finding, Report, Severity…)
│   ├── parser/              # document model: lines, frontmatter, refs
│   ├── pathsafe/            # pure-string path containment helpers
│   ├── platform/            # claude/codex/cursor/generic classification
│   ├── redact/              # secret and username masking
│   ├── report/
│   │   ├── text/            # terminal renderer (+ golden tests)
│   │   ├── json/            # skillguard-report/v1 renderer
│   │   ├── sarif/           # SARIF 2.1.0 renderer
│   │   ├── html/            # self-contained HTML renderer + template
│   │   └── reporttest/      # shared test fixtures for formatters
│   ├── rules/               # ASG001–ASG012 + ASG900, one file per concern
│   └── version/             # ldflags-injected build metadata
├── tools/covercheck/        # coverage gate used by CI and verify scripts
├── schemas/                 # JSON Schemas: config + JSON report
├── examples/
│   ├── safe-skill/          # scans clean (0 findings)
│   └── risky-skill/         # synthetic fixture triggering all 12 rules
├── docs/                    # this documentation tree (+ committed demos)
│   ├── decisions/           # architecture decision records
│   └── examples/            # committed deterministic demo reports
├── scripts/
│   ├── verify.sh / verify.ps1     # full local verification pipelines
│   ├── action-entrypoint.sh       # GitHub Action container entrypoint
│   └── test-action.sh             # local action contract test (no Docker)
├── .github/
│   ├── workflows/ci.yml     # CI (all actions pinned to commit SHAs)
│   └── ISSUE_TEMPLATE/      # bug / feature / rule-proposal templates
├── action.yml               # Docker-based GitHub Action definition
├── Dockerfile.action        # action image (bases pinned by digest)
├── .skillguard.yml          # this repo's own scan policy (dogfood)
├── Makefile                 # convenience targets (see scripts/ for Windows)
└── go.mod / go.sum          # module definition (yaml.v3 is the only dep)
```

## Layering rules

- `model`, `pathsafe`, `redact`, `version` depend on nothing internal.
- `parser`, `platform`, `config` depend only on the layer above.
- `rules` may import `parser`, `config`, `model`, `pathsafe`, `redact` —
  never `discovery` or `report/*`.
- `report/*` import only `model` (and each other never).
- `app` is the sole composition point and the only package that touches
  `os` for scanning purposes.
- Anything in `internal/` is unimportable from outside the module by Go's
  visibility rules — the CLI is the public interface, plus the report
  schemas in `schemas/`.

Deviations from the original sketch are deliberate and documented:
`internal/pathsafe` was added to keep containment logic pure and exhaustively
testable, and `internal/report/reporttest` exists so all four formatters are
tested against the identical fixture.
