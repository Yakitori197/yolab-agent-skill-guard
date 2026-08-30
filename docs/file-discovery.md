# File discovery

Discovery decides what gets read at all — it is the privacy gate. Everything
here happens before any file content reaches the parser or rules.

## Candidates

Files with `.md`, `.markdown`, or `.mdc` extensions (case-insensitive) are
candidates. Each candidate must then pass, in order:

1. **Sensitivity gate** (below) — checked first, from the name alone, before
   anything is opened. For a symlink the rule is applied to the link name and
   again to the resolved target name.
2. **Config `exclude`** — skipped with reason `config-exclude`.
3. **Config `include`** — when a non-empty include list exists, non-matching
   candidates are skipped with reason `not-in-include-list`.
4. **Size limit** — directory metadata over `max_file_size` skips with
   `exceeds-max-file-size`; the limit is enforced again from the open handle.
5. **Platform filter** — files whose classified platform is disabled are
   silently out of scope.

Binary content is decided at read time (below), not here, so no file is opened
twice.

Candidates are scanned in sorted path order (byte order of the root-relative
slash path), which makes output order independent of filesystem enumeration
quirks.

## Reading a candidate

Discovery itself never opens a file. Everything a candidate needs before its
content is touched (name sensitivity, config include/exclude, size, platform)
is decided from directory metadata; the content is then read exactly once, by
`discovery.ReadCandidate`, which:

1. `Lstat`s the path and, when it is a symlink, resolves it, re-checks that the
   target is inside the scan root, and applies the never-read name rules to the
   **resolved** name as well — so `alias.md → .env` is refused, not read.
2. Opens the file and takes size and mode from the **open handle**, not from
   the earlier stat.
3. Reads through a bounded reader capped at `max_file_size + 1` bytes, so an
   oversized file is detected without ever holding it in memory.
4. Checks every byte it actually read for NUL bytes; binary content is skipped
   by content, never trusted by extension in either direction.

**Residual TOCTOU risk.** One open per file keeps the window between the checks
and the read as small as the platform allows, and every check that can be made
from the open handle is made there. An attacker who can rewrite the tree
*during* a scan can still swap a path between `Lstat` and `open`; Go offers no
portable `openat`/`O_NOFOLLOW` equivalent across Windows, Linux, and macOS, so
this is documented rather than claimed away. Scanning a tree that a hostile
process is actively modifying is outside the model — check out a fixed revision
first, which is what the GitHub Action does.

## Never-read files

These are recognized **by name and skipped unopened**; they appear in every
report's skipped list so their existence is visible without their contents:

| Reason code | Matches |
|---|---|
| `env-file-never-read` | `.env`, `.env.*` |
| `key-material-never-read` | `.pem .key .p12 .pfx .ppk .jks .keystore` |
| `database-file-never-read` | `.db .sqlite .sqlite3 .mdb` |
| `archive-never-read` | `.zip .tar .gz .tgz .bz2 .xz .7z .rar .jar .war` |

These exclusions are hard-coded; configuration cannot re-include them.
Unrelated file types (source code, images, …) are simply out of scope and do
not clutter the skip list.

## Default excluded directories

Never entered, at any depth, reported once with reason
`default-excluded-dir`:

```text
.git node_modules vendor dist build coverage .next test-results playwright-report
```

## Symlinks

- A symlinked **file** is followed only when its resolved target stays inside
  the scan root. Containment is decided by filesystem identity, not by
  comparing lowercased strings: an exact canonical prefix settles the common
  case, and anything else is answered by walking the target's ancestors and
  asking `os.SameFile` whether one of them *is* the root directory. A
  directory whose name differs from the root's only by case is therefore
  accepted only where the filesystem really resolves both spellings to the
  same directory. Escaping links are reported as `symlink-outside-root` and
  never read.
- A symlinked **directory** is never descended (`symlink-dir-not-followed`),
  which also makes symlink cycles impossible to walk into; broken links and
  cycles surface as `unreadable`.

## Single-file mode

`skillguard scan path/to/FILE.md` scans exactly that file with its directory
as the root. It takes exactly the same route as a walked file: `Lstat` first,
symlinks resolved and containment-checked, sensitivity applied to both the link
name and the resolved name, then the same bounded read. Naming `.env` directly
still refuses to read it and reports it as skipped, and a symlink pointing out
of the root is refused rather than followed.

## Windows specifics

- Root-relative paths are always reported with forward slashes.
- Containment comparisons fold case, so `C:\Pkg` and `c:\pkg` are the same
  boundary; tests cover case-differing containment and UNC-shaped inputs.
