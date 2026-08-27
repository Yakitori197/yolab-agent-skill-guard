# Inspirations and originality

skillguard was designed after studying the public product direction of
several projects. **No code, rules, documentation text, or assets were
copied or adapted from any of them** — the concepts below were studied at the
"what exists / what's missing" level, and everything in this repository
(implementation, rule catalog, wording, tests, fixtures) is original work.

## What was studied, and what this project does differently

| Project | What it demonstrates | How skillguard differs |
|---|---|---|
| `anthropics/skills` | The SKILL.md package format and an official catalog of skills | skillguard is not a skill or a catalog — it is the *auditor* for such packages; the format's popularity is why validating it matters |
| `obra/superpowers` | Large community-curated skill collections spreading through installs | Exactly the distribution model that motivates pre-install auditing; skillguard adds the review tool that ecosystem lacks |
| `mattpocock/skills` | Skill/rules ecosystems spanning editors and agents | Confirms the multi-platform reality; skillguard classifies claude/codex/cursor/generic and applies per-platform expectations |
| `affaan-m/ECC` | Multi-agent configuration stacks with elaborate instruction files | Instruction files as production infrastructure — the more operational they get, the more they deserve CI gates |
| `projectdiscovery/nuclei` | A security scanner with a community rule catalog, severities, and CI outputs | Direction-level inspiration for "stable rule IDs + severity + machine-readable reports"; skillguard's engine, rule format, and rules share nothing with nuclei's YAML-template DSL — rules here are code with tests, scanning is offline-only |
| `langchain-ai/openwiki` | Docs-as-instructions pipelines | Reinforces that Markdown is executable-adjacent now; skillguard treats it with the suspicion previously reserved for code |

## The original positioning

The studied projects either *produce* instruction files or scan *code and
infrastructure*. skillguard occupies the gap between them: a purpose-built,
offline, deterministic auditor for the instruction files themselves —
validating structure (frontmatter, references, containment) and surfacing
security/privacy risk signals (secrets, destructive commands,
pipe-to-shell, injection phrasing, unpinned dependencies, obfuscation) with
CI-grade reports (SARIF/JSON/HTML) and a suppression governance model
(reasons required, expiry surfaced).

The rule catalog (ASG001–ASG012, ASG900), detection patterns, context model
(fence/prose/cautionary/blockquote scoring), package-root containment
semantics, configuration schema, report formats, and all fixtures were
designed and written for this project from scratch.
