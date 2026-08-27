# Security Policy

## Supported versions

The project is pre-release; only the latest commit on `main` receives
security fixes.

## What counts as a vulnerability here

skillguard's security promises are:

1. It never executes scanned content.
2. It never reads excluded sensitive files (`.env*`, key material, databases,
   archives) — they are reported as skipped by name only.
3. It never follows symlinks (or resolves references) outside the scan root.
4. It never transmits anything over the network at runtime.
5. It never emits an unmasked suspected secret or an absolute private path in
   any report format.
6. Scanned content cannot inject markup or script into the HTML report, or
   break the JSON/SARIF structure.

Anything that violates one of these promises is a security vulnerability —
please report it. Crashes on crafted input (parser panics) also qualify.

False positives/negatives in heuristic rules are quality issues, not
vulnerabilities; file a regular bug for those.

## How to report

Use **GitHub → Security → Report a vulnerability** (private vulnerability
reporting) on this repository. Please include a minimal reproduction file.
Do not open a public issue for exploitable problems.

Expect an acknowledgment within 14 days. Fixes land as ordinary commits with
credit in the changelog unless you prefer otherwise.

## Scope notes

- The GitHub Action runs entirely inside the runner with no secrets and
  `contents: read`; reports it writes stay in the workspace.
- Dependencies are minimal (`gopkg.in/yaml.v3`); CI runs `govulncheck` on
  every push.
