# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Best effort |
| < 0.1   | No        |

## Reporting a vulnerability

SkillSentry is itself a security tool, so a flaw in it deserves a private
report, not a public issue.

- **Email:** security@alicelabs.site
- Include: affected version/commit, a minimal input that reproduces the
  behavior (a SKILL.md or MCP config is ideal), and expected vs actual output.
- You will get an acknowledgment within 72 hours and a fix or a concrete plan
  within 30 days. We credit reporters in the CHANGELOG unless you prefer
  otherwise.

Please do **not** test against third-party deployments you don't own. The
dashboard binds to localhost by design; treat any networked instance as
someone else's property.

## What we consider in scope

- False negatives caused by non-deterministic engine behavior (results that
  depend on scan order or process state).
- Secret leakage through reports, evidence fields, or logs (the tool must
  never re-print the secrets it finds — see `maskSecret`).
- Injection through scanned content reaching the AI layer prompt in a way that
  changes the *scan verdict* of a different target.
- Path traversal or arbitrary file read via `scanPaths` inputs.

## Design boundaries (not vulnerabilities)

- SkillSentry is a review aid, not a sandbox: it never executes the skills it
  scans, but it also cannot guarantee a skill is safe — absence of findings is
  not a certificate.
- The optional semantic layer talks to a *local* OpenAI-compatible endpoint you
  configure; pointing it at a remote URL is explicitly supported via
  `--ollama-url`, and what it sends is documented (the scanned surfaces' text).
