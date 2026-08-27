# Testing

## Running

```bash
go test ./...                 # unit + integration
go test -race ./...           # race detector (CI enforces this on Linux)
sh scripts/verify.sh          # full pipeline (fmt, vet, tests, race,
                              # coverage gate, build, determinism, self-scan,
                              # action contract)
```

Windows equivalent: `powershell -File scripts/verify.ps1`. Where the race
detector cannot run because cgo has no C compiler (common on Windows), the
verify scripts say so explicitly instead of pretending it passed — the race
run in `.github/workflows/ci.yml` on Linux is the authoritative one.

## Suite map

| Area | Location | Highlights |
|---|---|---|
| Severity/model semantics | `internal/model` | ordering, fail-on, deterministic sort, fingerprints |
| Path safety | `internal/pathsafe` | `..`, mixed slashes, drive/UNC/`~`, percent-encoded traversal, case-folded containment |
| Parser | `internal/parser` | frontmatter (missing/duplicate/mistyped/malformed/oversized/unclosed), fences, inline code, CRLF, references, positions |
| Fuzzing | `internal/parser/fuzz_test.go` | `FuzzLoad`: crash-freedom + invariants on arbitrary bytes |
| Config | `internal/config` | fail-closed table (unknown fields, dup keys, bad globs, disable-everything), suppression validation/expiry, domain wildcards |
| Discovery | `internal/discovery` | `.env`/key/db/archive never read (including via symlink), bounded reads and size limits, binary content by content, include/exclude, symlink escape/cycle/dir, deterministic order |
| Rules | `internal/rules` | per-rule true positives, true negatives (prose words, placeholders, doc links), fixed severity, masking |
| Severity integrity | `internal/rules/negation_test.go` | conditional and plain prohibitions ("never X unless …", "never X, but run it now") keep the rule default severity; ASG006 findings survive disclaimers |
| Action path validation | `internal/actionpath` | traversal, POSIX/Windows/UNC absolutes, `~`, dash-leading, NUL/CR/LF/control, missing inputs, symlink escapes, the output parent-directory contract (missing parent, missing nested parents, a parent that is a regular file, a parent symlink pointing in and out), and unconditional output no-clobber (package.json, LICENSE, Makefile, Dockerfile, extensionless files, previous reports, hard links) verified with sentinel hashes |
| Report write layer | `internal/app/noclobber_test.go` | the `O_EXCL` write refuses every existing path and leaves it byte-identical; the plain CLI keeps its overwrite behavior |
| Report privacy | `internal/app/privacy_test.go` | no absolute scan root in text/JSON/SARIF/HTML or in any error message; `--show-paths` opt-in |
| Formatters | `internal/report/*` | golden files, byte-determinism double-renders, SARIF structural assertions, HTML XSS neutralization, JSON schema shape |
| CLI | `internal/app` | end-to-end exit codes 0/1/2, config discovery, suppressions (path + fingerprint + expiry), platform filter, validate mode, single-file scan, init no-overwrite, color control, `.env` never leaks |
| Action | `scripts/test-action.sh` | entrypoint contract in a throw-away workspace: happy paths, every hostile path/config/output rejection, output-clobber protection, missing-parent refusal (with nothing created on disk), `GITHUB_OUTPUT` shape; CI additionally runs the real Docker action |

## Golden files

Formatter outputs are pinned byte-for-byte under
`internal/report/*/testdata/*.golden`. Regenerate deliberately with:

```bash
go test ./internal/report/... -update
```

and review the diff — goldens are the output contract. `.gitattributes`
marks them `-text` so no platform ever rewrites their line endings.

## Coverage gate

```bash
go test -coverprofile=cover.out -coverpkg=./internal/... ./...
go run ./tools/covercheck -profile cover.out -min 90
```

The gate measures **aggregate statement coverage across all `internal/`
packages** (merged profile, blocks deduped across test binaries). CI fails
below 90%. `cmd/skillguard` is a `main()` shim excluded from the
measurement — it contains one statement and is exercised indirectly by every
CLI test through `app.Run`.

## Fixture policy

No credential-shaped literal is ever committed. Tests that need detectable
secrets assemble synthetic values at runtime (`"ghp_" + strings.Repeat(…)`),
and committed fixtures use obviously-fake placeholders. The risky example
package states in its own text that everything in it is synthetic.

## Link tests and CI

Tests that need real symlinks or hard links skip themselves where the OS forbids creating
them (unprivileged Windows). That must never turn into silent coverage loss, so
Linux CI:

- runs the symlink and hard-link security tests with `-v` and **fails the job** if any of
  them reports `--- SKIP`, and
- runs the action contract script with `SKILLGUARD_REQUIRE_SYMLINKS=1` and
  `SKILLGUARD_REQUIRE_HARDLINKS=1`, which turn a skipped symlink or hard-link
  section into a failure.
