# Limitations

Honest boundaries of the current implementation. None of these are hidden
behind marketing language; several have planned mitigations in the
[roadmap](roadmap.md).

## Inherent to the approach

- **Heuristics are heuristics.** Rules marked heuristic have irreducible
  false positives and false negatives. Findings are risk signals for a human
  reviewer, and severity is a prior, not a verdict.
- **Line-oriented matching.** Commands assembled across multiple lines
  (backslash continuations, string concatenation), or phrased in language the
  patterns do not anticipate, can evade detection. Conversely, merely
  discussing a dangerous command in prose yields a finding at the rule's full
  severity: nothing in the scanned text lowers it.
- **No semantic understanding.** The scanner does not interpret code blocks,
  does not resolve variables, and deliberately never decodes encoded content
  — a base64 blob is flagged by shape, not by what it contains.
- **English-centric patterns.** Injection and cautionary phrasing detection
  target English; instruction files in other languages get structural rules
  but weaker content heuristics.

## Current implementation bounds

- Severity is never lowered by the scanned text, so a document that teaches
  what *not* to do is reported exactly like one that instructs it. That is a
  deliberate bias toward over-reporting — the scanner cannot tell a lesson from
  a lure — and the intended answer is a reasoned, expiring suppression, not a
  quieter rule.
- Reading a candidate is one open per file, but Go has no portable
  `openat`/`O_NOFOLLOW`, so a tree being rewritten *during* a scan retains a
  small TOCTOU window (see [file-discovery.md](file-discovery.md)).
- Matching is capped at 64 KiB per line and 256 KiB of frontmatter; content
  past a cap on the *same line* is not matched (files up to `max_file_size`
  are fully line-iterated).
- Reference extraction covers inline links/images, reference definitions,
  and autolinks — not HTML `<a href>` inside Markdown, and not link targets
  split across lines.
- `fish`-style exotic shells and uncommon downloaders are not in the ASG004
  pattern set.
- ASG005 treats prose URLs as network intent only when the line contains a
  transmission verb; a sufficiently oblique instruction evades it.
- Windows reserved device names and NTFS alternate data streams are not
  specifically modeled (they surface as unreadable at worst).
- The Docker action builds from source per run (no prebuilt image), which
  costs ~a minute of CI time and requires the runner to reach the Go module
  proxy at *build* time — scanning itself remains offline.
- SARIF output is validated structurally and against GitHub's documented
  ingestion rules by tests, but has not yet been run through an external
  SARIF validator service (kept offline deliberately).

## Out of scope by design

Runtime behavior monitoring, network reputation lookups, LLM-based content
judgment, auto-fixing scanned files, and scanning binary artifacts. See
[product-spec.md](product-spec.md) for the rationale.
