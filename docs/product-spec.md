# Product specification

## One sentence

skillguard is an offline-first, read-only auditor that finds security,
privacy, and compatibility risk signals in AI agent skill and instruction
files, and reports them deterministically for humans and CI.

## Who it is for

- **Skill authors** who want their package to be safe to publish: no leaked
  paths or tokens, no broken references, a manifest every host accepts.
- **Skill consumers** who install community skills and want a structured
  review before an agent reads them with high trust.
- **Repository owners** who keep `AGENTS.md` / `CLAUDE.md` / `.cursor` rules
  in their repos and want CI to hold those files to the same bar as code.

## What it does

1. **Discovers** instruction files under a root (or a single named file),
   applying privacy exclusions before anything is opened
   ([file-discovery.md](file-discovery.md)).
2. **Parses** each file into an annotated read-only model: YAML frontmatter
   with per-node positions, line contexts (frontmatter / code fence /
   inline code / blockquote / prose), and Markdown references.
3. **Evaluates** the rule catalog ([rules.md](rules.md)) against that model.
   Rules are pure text analyses; several consult the configuration (allowed
   domains, capabilities) or check reference existence inside the root.
4. **Post-processes**: severity overrides, fingerprints, suppressions
   (with expiry), deterministic ordering.
5. **Renders** the identical finding set as text, JSON, SARIF, or HTML, and
   exits 0/1/2 according to the `fail-on` threshold.

## What it deliberately is not

- **Not a sandbox or runtime monitor.** It never executes anything, so it
  cannot observe behavior — only text.
- **Not a malware verdict engine.** Heuristic findings are risk signals with
  documented false-positive modes; the wording never claims intent.
- **Not an LLM product.** No model, no API key, no network. Determinism and
  auditability outrank cleverness.
- **Not a general Markdown linter.** Style is out of scope; only structure,
  security, privacy, and compatibility are in scope.

## Non-negotiable properties

| Property | Meaning |
|---|---|
| Offline | Zero network use at scan time, ever |
| Read-only | Scanned content is never executed, rendered, or resolved remotely |
| Privacy-preserving | Sensitive files unopened; secrets masked; no absolute private paths in reports |
| Deterministic | Identical input ⇒ byte-identical JSON/SARIF/HTML, stable finding order |
| Fail-closed | Any configuration or input error exits 2 rather than scanning less than asked |
| Honest | Reports say what was skipped and why; heuristics are labeled as such |

## Success criteria for v0.1

- The bundled `examples/safe-skill` scans clean; `examples/risky-skill`
  demonstrates all twelve detection rules.
- The repository scans itself clean at `--fail-on high` in CI.
- Reports pass GitHub Code Scanning ingestion (SARIF 2.1.0).
- Aggregate statement coverage across `internal/` ≥ 90% with the race
  detector green on Linux CI.
