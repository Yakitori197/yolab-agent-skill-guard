# Architecture

## Data flow

```text
path argument
     │
     ▼
internal/app        CLI parsing, config resolution, exit codes
     │
     ▼
internal/discovery  walk root → candidates + skipped (privacy gate lives here)
     │
     ▼
internal/parser     bytes → Document (lines, contexts, frontmatter, refs)
     │
     ▼
internal/rules      Document + Context → []Finding   (pure text analysis)
     │
     ▼
internal/app        post-process: overrides, fingerprints, suppressions, sort
     │
     ▼
internal/report/*   one Report → text | json | sarif | html
```

## Package responsibilities

| Package | Responsibility | May not do |
|---|---|---|
| `cmd/skillguard` | `main()` shim only | contain logic |
| `internal/app` | command dispatch, engine orchestration, exit codes | render formats itself |
| `internal/config` | parse + validate `.skillguard.yml`, glob compilation, suppression matching | read files other than what app hands it |
| `internal/discovery` | walking, default exclusions, sensitive-file gate, symlink containment, and the single bounded content read (`ReadCandidate`) | read anything a name-based rule already refused |
| `internal/parser` | line model, fence/blockquote/inline-code annotation, frontmatter (yaml.v3 behind a recover guard), reference extraction | touch the filesystem |
| `internal/platform` | classify path → platform + package root | read files |
| `internal/rules` | the catalog; every rule consumes a `Document` and an injected `Context` | perform I/O directly (existence checks are injected functions) |
| `internal/actionpath` | validate and resolve CI-wrapper path inputs (containment, symlinks, control characters) | be bypassed by the entrypoint shell |
| `internal/redact` | masking of secrets and username path segments | — |
| `internal/pathsafe` | pure-string path normalization, traversal and containment checks | touch the filesystem |
| `internal/report/{text,json,sarif,html}` | render a finished `model.Report` | re-run scanning, sort, or mutate findings |
| `internal/model` | shared types, severity ordering, deterministic sort, fingerprints | depend on any other internal package |
| `internal/version` | ldflags-injected build metadata | fabricate values |
| `tools/covercheck` | CI/local coverage gate | — |

## Key design points

- **One report model, four renderers.** Formatters receive a finished,
  sorted `model.Report`; they cannot disagree with each other because they
  cannot recompute anything.
- **Injected filesystem.** Rules see `FileExists` / `ResolveReal` functions.
  Tests simulate any layout (including symlink escapes) without a real disk,
  and no rule can quietly grow direct I/O.
- **Contexts are metadata, not mitigation.** The parser annotates every line
  (frontmatter, fenced code + language, inline code, blockquote) and every
  finding records where it matched — but nothing in the scanned text can change
  a severity, remove a finding, or alter the exit code. Exceptions live in the
  configuration, where they are visible, reasoned, and expiring.
- **Fail-closed configuration.** `config.Parse` rejects unknown fields,
  duplicate keys, unbounded suppressions, traversal in globs, and
  disable-everything configs; the app converts any of that into exit 2.
- **No global state, no init-time I/O.** All regexes compile at package
  variable initialization (CPU only); everything else is constructed per run.
- **Sequential scanning.** Files are processed in sorted order on one
  goroutine: determinism is trivial and no goroutine can outlive its work.

## Determinism inventory

Ordering: findings sort by path → line → column → rule ID; skipped entries by
path → reason; candidates by path; SARIF rule array by rule ID (catalog
order). Encoding: `encoding/json` with fixed struct field order (Go sorts the
one map — partialFingerprints — alphabetically); `html/template` over
pre-sorted slices. Content: no timestamps, no absolute paths, no environment
strings; the tool version is the only run-varying field and is pinned by the
build. See [ADR-0003](decisions/0003-deterministic-reports.md).
