---
name: release-notes-writer
description: Draft release notes from a merged changelog section, following the team style guide bundled with this skill.
version: "1.0.0"
license: MIT
allowed-tools:
  - Read
  - Grep
---

# Release Notes Writer

Draft release notes for the current release using only files inside this
package and the repository being worked on.

## Steps

1. Read the style rules in [references/style-guide.md](references/style-guide.md).
2. Collect the `Unreleased` section of the repository changelog.
3. Group entries by audience impact (breaking, feature, fix) as described in
   the [checklist](references/checklist.md).
4. Draft the notes in the repository's existing tone. Keep every claim
   traceable to a changelog entry.

## Boundaries

- Work offline: this skill needs no network access.
- Never modify files; produce a draft for the user to review.
- If the changelog has no `Unreleased` section, report that instead of
  inventing content.
