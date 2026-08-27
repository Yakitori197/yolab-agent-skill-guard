# ADR-0003: Deterministic reports

- Status: accepted
- Date: 2026-08-26

## Context

The primary consumer is CI: diffs between runs, golden tests, caching, and
"did anything change?" questions all require that identical inputs produce
identical bytes. Typical nondeterminism sources — timestamps, map iteration,
filesystem enumeration order, absolute paths, locale — had to be excluded
structurally, not by convention.

## Decision

Byte-for-byte determinism is a tested guarantee for JSON, SARIF, and HTML
(and de facto for text):

- **Ordering.** Findings sort by normalized path → line → column → rule ID;
  skipped files by path → reason; candidates scan in sorted path order; the
  SARIF rule array follows catalog (ID) order. No output ever iterates a Go
  map (the single map in SARIF, `partialFingerprints`, is key-sorted by
  `encoding/json`).
- **Content.** No timestamps anywhere; no absolute paths (root-relative
  slash paths only; the scan root appears in no machine format); the tool
  version is build-injected and constant for a build.
- **Encoding.** Struct-defined field order, two-space indent, trailing
  newline, LF-only line endings on every platform (goldens are protected by
  `.gitattributes`).
- **Clock use.** The only time-dependent behavior is suppression *expiry*,
  which affects which findings exist, not how they serialize; the clock is
  injected (`App.Now`) so tests pin it, and same-input runs on the same day
  are identical. Reports never embed the evaluation time.
- **Enforcement.** Golden tests pin exact bytes; double-render tests assert
  `render(x) == render(x)`; the verify scripts and acceptance runs hash two
  consecutive real scans per format and compare.

## Consequences

- A changed report byte always means a changed input, rule, or deliberate
  format revision (with goldens updated in the same commit) — ideal for
  review.
- Formatters must never "helpfully" add run metadata; anything like a scan
  timestamp is rejected in review. If a use case ever truly needs embedded
  run metadata, it will be an explicitly non-deterministic opt-in mode, off
  by default, and outside the current schema guarantees.
