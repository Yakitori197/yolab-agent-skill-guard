# ADR-0002: Offline security model

- Status: accepted
- Date: 2026-08-26

## Context

skillguard reads files written by potential adversaries, and its reports are
shared onward. Two failure classes would be fatal for a *security* tool: the
scanner becoming an attack vector itself (executing payloads, leaking data,
escaping the scan root), and the tool sending data anywhere or depending on
anything network-side (telemetry, cloud rules, LLM calls) that users cannot
audit.

## Decision

Adopt a hard offline, read-only model as an invariant rather than a mode:

1. **No execution pathways exist.** No `os/exec`, no eval, no decoding of
   flagged payloads. Analysis is text-only.
2. **No network pathways exist at runtime.** No update checks, no telemetry,
   no remote rule feeds. Anything network-shaped belongs to build/CI time.
3. **Privacy gate before I/O.** Sensitive names (`.env*`, keys, databases,
   archives) are excluded before `open()`; binary sniffing distrusts
   extensions; size caps bound memory; these exclusions are not
   configurable off.
4. **Containment before resolution.** References and symlinks are
   lexically resolved and containment-checked (case-folded where the OS
   does) before any filesystem probe; escapes are findings, not reads.
5. **Redaction at the source.** Secret matches are masked when the finding
   is constructed, so no later layer can leak what it never received; the
   scan root never enters machine-readable output.
6. **Fail closed.** Configuration or input errors abort with exit 2 —
   silently narrowing a scan is treated as worse than not scanning.

## Consequences

- Users can run skillguard on their most sensitive repositories and share
  the SARIF publicly with a clear conscience; the promises are testable and
  tested (see [docs/security-model.md](../security-model.md)).
- The tool cannot benefit from online intelligence (reputation feeds, model
  judgment). Accepted: determinism and auditability are the product.
- Some UX costs: no auto-update, no "check this hash online" helpers, and
  encoded payloads are only ever described, never expanded.
