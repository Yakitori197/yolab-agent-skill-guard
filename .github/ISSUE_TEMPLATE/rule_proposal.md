---
name: Rule proposal
about: Propose a new detection rule (next free ASG id)
title: "Rule proposal: "
labels: rule-proposal
assignees: ""
---

## Risk being detected

<!-- What real-world failure or attack does this catch in skill/instruction files? -->

## Detection sketch

<!-- Patterns / structural checks. Remember: text analysis only, no execution. -->

## True positives (synthetic examples)

```markdown
(safe-to-publish synthetic example that should be flagged)
```

## Known false-positive risks

<!-- What benign text could match, and how does the pattern avoid matching it?
     Note: a rule may not lower its own severity based on the scanned text —
     severity comes from the rule alone. Narrow the pattern instead. -->

## Proposed metadata

- Default severity (critical/high/medium/low/info) and why:
- Category:
- Heuristic (yes/no):
- Remediation advice:
