# skillguard documentation

Everything about the project, organized by concern. Every page describes the
implementation as it exists; planned work lives only in the
[roadmap](roadmap.md).

## Product

- [Product specification](product-spec.md) — what skillguard is and is not.
- [Inspirations](inspirations.md) — prior art studied, and how this project
  differs (no code was copied from any of them).
- [Limitations](limitations.md) — honest boundaries of the approach.
- [Roadmap](roadmap.md) — planned, not yet implemented.

## Using skillguard

- [CLI reference](cli.md) — commands, flags, exit codes.
- [Configuration](configuration.md) — `.skillguard.yml`, schema, examples.
- [Rules catalog](rules.md) — ASG001–ASG012 and ASG900 in depth.
- [File discovery](file-discovery.md) — what gets scanned, skipped, and why.
- [Platform support](platform-support.md) — claude / codex / cursor / generic.
- [GitHub Action](github-action.md) — CI integration and SARIF upload.

## Reports

- [Text report](report-text.md)
- [JSON report](report-json.md) (+ [JSON Schema](../schemas/report.schema.json))
- [SARIF report](report-sarif.md)
- [HTML report](report-html.md)
- Committed demos: [risky-report.html](examples/risky-report.html) ·
  [risky-report.sarif](examples/risky-report.sarif) ·
  [risky-report.json](examples/risky-report.json)

## Security and privacy

- [Security model](security-model.md) — the six enforced promises.
- [Threat model](threat-model.md) — assets, adversaries, mitigations.
- [Privacy](privacy.md) — what never leaves your machine (everything).
- [Accessibility](accessibility.md) — HTML report accessibility posture.

## Engineering

- [Architecture](architecture.md) — packages and data flow.
- [Project structure](project-structure.md) — directory-by-directory map.
- [Testing](testing.md) — suites, golden files, fuzzing, coverage gate.
- [Dependencies](dependencies.md) — the single third-party module, justified.
- [Release process](release-process.md) — how a release will be cut.

## Decisions

- [ADR-0001: Language and runtime](decisions/0001-language-and-runtime.md)
- [ADR-0002: Offline security model](decisions/0002-offline-security-model.md)
- [ADR-0003: Deterministic reports](decisions/0003-deterministic-reports.md)
