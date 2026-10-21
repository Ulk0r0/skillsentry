# Contributing to SkillSentry

Thanks for helping harden the agent supply chain. This project has two hard
invariants — everything else is negotiable:

1. **Zero runtime dependencies.** `packages/skillsentry` must not gain any
   `dependencies` entry. Dev dependencies (vitest, eslint, typescript) are fine.
2. **The clean gallery must stay clean.** `samples/skills/clean` and
   `samples/mcp/clean` must scan with zero medium+ findings. If your change
   flags them, the rule is too noisy — calibrate it.

## Quick start

```bash
git clone https://github.com/Ulk0r0/skillsentry
cd skillsentry && npm install
npm test          # full suite (determinism, rules, parsers, CLI, reports)
npm run lint      # ESLint, zero warnings tolerated
npm run typecheck # strict TS, noUncheckedIndexedAccess on
```

## The fastest ways to help

- **Add poisoned fixtures we don't catch yet.** Drop a `SKILL.md` under
  `samples/skills/poisoned/<name>/`, open a PR describing the real-world
  pattern it represents. If it doesn't trigger a rule, we extend the rules —
  your fixture becomes a permanent regression test.
- **Add clean documents we flag by mistake** (false positives). They harden
  precision — the other half of a security tool's credibility.
- **Improve remediation texts.** Every finding tells a maintainer what to do
  instead; if a text is vague, that's a bug.

## Determinism is tested

`test/determinism.test.ts` asserts that the same content produces the same
findings regardless of what was scanned before it in the same process. If you
introduce shared mutable state (module-level regexes with `exec`/`test`,
caches keyed by nothing), this suite will catch it — keep it that way. Rules
must read text through the stateless helpers in `src/util/text.ts`
(`firstMatch`, `matches`, `allMatches`) instead of calling `exec`/`test` on
shared patterns.

## Rules workflow (SS-001…SS-009)

Each rule is a pure function `run(surface, target) → RawMatch[]` documented
against its OWASP mapping in `src/mapping.ts`. When adding a pattern:

- Quote real attack phrasing in the comment above the pattern (where did you
  see it? which report?).
- Prefer high-precision patterns; a rule that cries wolf gets ignored.
- Add one positive test (should be caught) and one negative test (legitimate
  text that must NOT be caught) in `test/rules.test.ts`.
- Every finding carries evidence + remediation: never leak the secret it
  matched (see `maskSecret` in SS-008).

## Commit style

Short imperative subject (`fix: dedupe overlapping blob spans`), body explains
the *why*. We don't enforce a spec, but CHANGELOG entries under `[Unreleased]`
are expected for user-visible changes.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md) — please do not open public issues for
exploitable behavior in SkillSentry itself.

## License

By contributing you agree that your contributions are licensed under the
[MIT License](LICENSE).
