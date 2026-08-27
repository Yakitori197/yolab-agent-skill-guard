# Accessibility (HTML report)

The HTML report targets WCAG 2.1 AA for its core reading and navigation
experience, within the constraint of being a single static file with no
JavaScript.

## What is implemented

- **Semantic structure.** `header` / `main` / `section` landmarks, one `h1`,
  hierarchical `h2`/`h3`, real tables with `th scope="col"`, definition lists
  for finding details, and `lang="en"` on the root element.
- **Keyboard operability.** The only interactive element is the native
  `<details>/<summary>` disclosure, fully keyboard-operable by default, with
  a visible `:focus-visible` outline driven by the accent color token.
- **Color and contrast.** Both light and dark palettes (switched by
  `prefers-color-scheme`) use text/background pairs chosen for ≥ 4.5:1
  contrast on body text; severity is conveyed by the severity *word*, never
  by color alone.
- **Responsive layout.** Fluid single-column layout; wide tables scroll
  inside their own `overflow-x` container so the page never scrolls
  horizontally; content reflows at narrow widths and high zoom.
- **No motion, no autoplay, no timers.** The page is fully static.
- **Screen-reader considerations.** Sections are labeled via
  `aria-labelledby`; summary rows read as "severity, position, rule ID,
  title, message" in that order.

## Known gaps (tracked honestly)

- The severity summary cards repeat information available in prose; they are
  presentational and not marked `aria-hidden`, which produces some verbosity
  in screen readers.
- No skip-navigation link yet (single-page document with landmarks; low
  impact, still worth adding).
- Contrast has been verified against the token table by calculation, not yet
  by an external audit tool run; an automated check is on the
  [roadmap](roadmap.md).
