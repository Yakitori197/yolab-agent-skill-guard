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
| Path safety | `internal/pathsafe` | `..`, mixed slashes, drive/UNC/`~`, percent-encoded traversal, package containment with and without case folding |
| Case-resolution probe | `internal/discovery/foldscase_test.go` | `FoldsCase` answers about the directory's *own* contents, not about how its parent spells it: a deterministic fake models the mixed parent/child semantics Windows allows (case-insensitive parent + case-sensitive directory and the reverse), the probe is asserted to look only inside the directory, every uncertain outcome answers false, and the real filesystem is cross-checked with `os.SameFile` and proven unchanged by the probe. Two ways of fooling identity are pinned: case-different entries hard-linked to one inode (fake, and a real `os.Link` on Linux) must not read as folding, and a name whose runes report as cased but whose simple mapping does not move them (U+00DF, U+00AA) must yield no alternative spelling at all |
| Filesystem containment | `internal/discovery/containment_test.go` | inside/outside paths, symlink targets in and out, a symlinked root, a **case-only sibling directory** (asserted against `os.SameFile`, with the physical half skipped honestly on a case-folding filesystem), a **Unicode case-folding sibling** (U+212A lowercases to `k` but is a different directory on every mainstream filesystem, so this one runs physically everywhere), fresh output leaves, missing parents, and fail-closed behavior on a missing root or a relative candidate; `FoldsCase` is asserted against the filesystem, never against `runtime.GOOS` |
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
| Terminal safety | `internal/termsafe`, `internal/report/text/hostile_test.go`, `internal/app/terminal_test.go`, `internal/app/flagsafety_test.go` | escapes for C0/C1 controls, bidi overrides and isolates, zero-width characters, BOM, line/paragraph separators and malformed UTF-8; printable text (including Traditional Chinese) unchanged; `--no-color` output free of ESC; color output carrying only the renderer's own ANSI; a hostile path unable to forge a finding, summary, or result line; hostile CLI arguments, a bidi-override filename exercising the success branch of the "report written to" line, and a hostile filename on disk driven end to end through the real CLI; an ANSI clear-screen used as a flag name against every command that parses flags (including `scan`'s second parse pass after the path), asserting stderr stays inert, the payload is still visible, and the usage block keeps its own layout; plus a source-reading guard that fails if any file outside `safeout.go` builds a flag set or writes to a stream directly |
| CLI | `internal/app` | end-to-end exit codes 0/1/2, config discovery, suppressions (path + fingerprint + expiry), platform filter, validate mode, single-file scan, init no-overwrite, color control, `.env` never leaks |
| Action | `scripts/test-action.sh` | entrypoint contract in a throw-away workspace: happy paths, every hostile path/config/output rejection, output-clobber protection, missing-parent refusal (with nothing created on disk), `GITHUB_OUTPUT` shape, and a U+202E output filename proving the report lands on exactly the requested path with the value reaching `GITHUB_OUTPUT` byte for byte; CI additionally runs the real Docker action |
| Entrypoint emission | `internal/app/entrypoint_guard_test.go`, `scripts/test-action.sh` | a portable guard reads `scripts/action-entrypoint.sh` and fails on any `echo`, because the XSI `echo` on Alpine and Debian interprets backslash escapes inside a legal POSIX filename; the shell script additionally drives `a\tb.json`, `a\nb.json`, `a\cb.json` and `a\rb.json` end to end where the filesystem can express them, asserting the report lands on the exact path, `GITHUB_OUTPUT` carries it byte for byte, and no extra line was forged |
| Machine protocol | `internal/app/machineout_test.go` | `action-paths` output is verbatim, never escaped: a legal U+202E path round-trips byte for byte and the human escape never appears; CR/LF/NUL/ESC/C1 in the workspace, path, config or output are refused with nothing written to stdout; the writer is all-or-nothing and its error names the key, not the value. Kept separate from the JSON/SARIF escaping tests — different protocol, different rule |

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

Some filesystem tests skip themselves where the platform cannot express the
case at all: real symlinks and hard links need privileges unprivileged Windows
does not grant, a case-only sibling directory cannot exist on a case-folding
filesystem, and a filename containing ESC or a newline cannot exist on Windows.
That must never turn into silent coverage loss, so Linux CI:

- runs those filesystem security tests (symlink, hard-link, case-only sibling,
  hostile filename on disk) with `-v` and **fails the job** if any of them
  reports `--- SKIP`, and
- runs the action contract script with `SKILLGUARD_REQUIRE_SYMLINKS=1` and
  `SKILLGUARD_REQUIRE_HARDLINKS=1`, which turn a skipped symlink or hard-link
  section into a failure.
