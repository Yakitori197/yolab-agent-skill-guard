# HTML report

`--format html` writes one completely self-contained page. A committed
example: [`docs/examples/risky-report.html`](examples/risky-report.html) —
download and open it offline; nothing else is required.

## Contents

- Verdict banner (PASS/FAIL against the fail-on threshold).
- Severity summary cards; findings-by-rule and findings-by-platform tables.
- Findings grouped by file. Each finding is a native `<details>` disclosure:
  the summary row shows severity, `line:column`, rule ID, title, a
  "heuristic — requires review" badge where applicable, and the message; the
  body reveals the rule rationale, remediation, and the fingerprint.
- The skipped-files table (path + reason — contents were never read).
- A footer restating the privacy posture.

## Security properties

- **No JavaScript at all** — interactivity is native `<details>` only.
- **Strict CSP** (`default-src 'none'; style-src 'unsafe-inline'`), inline
  CSS only: no external requests of any kind, no fonts, no analytics, no
  tracking.
- **Contextual escaping** — every value passes through Go's `html/template`;
  adversarial fixtures assert that `<script>` and attribute-breaking payloads
  in scanned content render inert.
- **No absolute paths, no timestamps, masked secrets** — same content rules
  as every other format, byte-identical across runs.

## Presentation

- Responsive single-column layout; tables scroll horizontally inside their
  own containers on narrow screens.
- Light and dark palettes via `prefers-color-scheme`.
- Accessibility posture and known gaps: [accessibility.md](accessibility.md).
