# Roadmap

Planned, **not implemented**. Nothing below is promised for a date; items
move into the changelog only when they actually land.

## Near term (v0.1 → v0.2)

- First tagged release with checksummed cross-platform binaries and the
  README action example pinned to a real commit SHA.
- `--format` multi-output in one run (e.g., text to stdout + SARIF to file)
  so CI does not scan twice.
- ASG013 candidate: sensitive-file *references* (instructions telling an
  agent to open `.env`/key files) — today only the files themselves are
  gated.
- Config `extends` for sharing an org-level baseline policy.
- Automated accessibility audit of the HTML report in CI.

## Middle term

- Multi-line command reassembly (continuation-aware matching) to close the
  main ASG003/ASG004 evasion route.
- Language packs for non-English injection/cautionary phrasing.
- HTML `<a href>` reference extraction.
- A `--baseline` mode: suppress everything currently present, fail only on
  new findings (adoption path for existing repositories).
- Rule metadata export (`skillguard rules --format json`) for tooling.

## Exploratory

- Marketplace publication of the action (with a prebuilt, digest-pinned
  image to remove build-time network needs).
- Editor integration (LSP diagnostics) reusing the JSON report.
- Signed release provenance (SLSA-style attestations).

## Explicit non-goals

See [product-spec.md](product-spec.md#what-it-deliberately-is-not) — online
lookups, LLM judgment, and auto-fix remain out of scope regardless of
roadmap stage.
