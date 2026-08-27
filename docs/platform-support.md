# Platform support

skillguard classifies every scanned file into one platform, which drives
manifest expectations (ASG009), package-root containment (ASG007), and the
`--platform` / `platforms:` filters.

## Classification

Evaluated per file, most-specific first:

| Rule | Platform | Package root |
|---|---|---|
| basename `SKILL.md` (any case) | `claude` | its own directory |
| basename `AGENTS.md` | `codex` | nearest enclosing skill dir, else scan root |
| basename `CLAUDE.md` | `claude` | ditto |
| extension `.mdc` | `cursor` | ditto |
| any path segment `.claude` | `claude` | ditto |
| any path segment `.cursor` | `cursor` | ditto |
| inside a directory (or subtree) containing `SKILL.md` | `claude` | that skill directory |
| everything else (`*.md`, `*.markdown`) | `generic` | scan root |

A directory containing `SKILL.md` is a **skill package**: every file in its
subtree belongs to it, and references from those files that leave the package
directory are flagged by ASG007 (medium) even when they stay inside the scan
root — skills must be self-contained to be portable.

## Per-platform expectations

### `claude`

- `SKILL.md` requires frontmatter with non-empty string `name` and
  `description`; conventional names are lowercase-hyphen (`low` finding
  otherwise); `allowed-tools` must be a list and is inspected by ASG006.
- `.claude/commands/*.md` and other package files get full content rules but
  no SKILL-specific manifest requirements.

### `codex`

- `AGENTS.md` has no required frontmatter. If frontmatter exists it must be
  valid YAML (ASG009 generic checks). All content rules apply.

### `cursor`

- `.mdc` rules may carry frontmatter; when present, `description` must be a
  string, `globs` a string or list, `alwaysApply` a boolean.

### `generic`

- Any other Markdown instruction file. No manifest requirements beyond
  well-formed frontmatter *if* frontmatter is present; all content rules
  apply. This deliberately includes files like `README.md` — repositories
  that consider that noise can scope with `include:`/`exclude:` or
  `--platform`.

## Filtering

`--platform claude --platform cursor` (repeatable flag) or `platforms:` in
config restricts scanning; files of other platforms are not read and not
counted. The flag replaces the config list when both are given.
