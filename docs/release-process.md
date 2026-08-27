# Release process

No release has been cut yet; this documents how the first one will happen.
Nothing here runs automatically — releasing is a deliberate human act.

## Versioning

Semantic versioning, starting at `v0.1.0`. Rule IDs and report schemas are
the compatibility surface:

- Adding a rule or an additive report field → minor.
- Changing a rule's meaning, removing output fields, changing exit-code
  semantics → major (post-1.0) and a schema bump where applicable.
- Rule IDs are never renamed or reused, ever.

## Checklist

1. `sh scripts/verify.sh` green locally; CI green on `main` (including
   Linux race run and action smoke test).
2. `CHANGELOG.md`: move `[Unreleased]` into a dated version section.
3. Regenerate demo reports (`make demo`) — the diff must be empty unless the
   release intentionally changed output.
4. Tag: annotated `vX.Y.Z` on the release commit.
5. Build artifacts (manually or via a future release workflow) with real
   metadata injected:

   ```bash
   go build -trimpath -ldflags "\
     -X github.com/Yakitori197/yolab-agent-skill-guard/internal/version.Version=vX.Y.Z \
     -X github.com/Yakitori197/yolab-agent-skill-guard/internal/version.Commit=<commit> \
     -X github.com/Yakitori197/yolab-agent-skill-guard/internal/version.Date=<yyyy-mm-dd>" \
     ./cmd/skillguard
   ```

   Local builds keep `dev`/`unknown` — values are injected, never fabricated.
6. Publish checksums (SHA-256) alongside binaries for
   linux/windows/darwin × amd64/arm64.
7. Update the README action example from `@<pinned-commit-sha>` placeholder
   to the real released commit SHA.

## Explicit non-steps (for now)

No Marketplace listing, no package-registry publication, no auto-release
workflow, no announcement automation. Each of those is a separate future
decision recorded in [roadmap.md](roadmap.md).
