# ADR-0001: Language and runtime

- Status: accepted
- Date: 2026-08-26

## Context

The tool must ship as a trustworthy single binary on Windows, Linux, and
macOS; run in CI containers without a language runtime; process hostile text
without crashing; and keep its supply chain small enough to audit by hand.
Candidates considered: Go, Rust, TypeScript/Node, Python.

## Decision

**Go**, with the standard library for everything except YAML
(`gopkg.in/yaml.v3` — see [docs/dependencies.md](../dependencies.md)).

Minimum version: **`go 1.26`** in `go.mod`. Rationale: the project was built
with the then-current Go 1.27; upstream supports the latest two release
lines, so 1.26 is the *oldest still-supported* floor — new enough for the
toolchain features used, old enough not to force the newest release on
users, exactly matching the "reasonable and still supported" requirement.
The floor rises only when a needed feature or the support window demands it.

## Consequences

- Single static cross-compiled binary (`CGO_ENABLED=0`); the Docker action
  builds from source with no runtime dependencies in the final image.
- Go's RE2 regexp engine gives linear-time matching — catastrophic
  backtracking is impossible by construction, which matters when every input
  is adversarial.
- `html/template` provides contextual auto-escaping for the HTML report;
  `encoding/json` provides deterministic struct-ordered output.
- Trade-offs accepted: no Rust-grade memory guarantees (mitigated by Go's
  memory safety), no npm-ecosystem UI components for the HTML report (which
  the no-JS requirement forbids anyway), and one third-party YAML dependency
  (no stdlib YAML) run behind recover guards.

## Alternatives rejected

- **Rust**: strongest safety story, but slower iteration for this codebase's
  size and no team advantage; Go's determinism/stdlib coverage sufficed.
- **Node/TypeScript**: contradicts "no Node.js required" and drags a large
  transitive dependency tree into a security tool.
- **Python**: runtime requirement on scanned machines and slow cold starts
  in CI; packaging a single binary is a project in itself.
