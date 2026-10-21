# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-10-21

Quality and stability release: every known defect closed, determinism now
guaranteed by test, professional tooling (strict TypeScript, ESLint type-checked
at zero warnings) and governance docs. The scanning API is unchanged.

### Fixed
- **Order-dependent results (determinism violation).** Module-level `/g` regexes
  kept `lastIndex` between files; a target scanned after another could lose its
  CRITICAL SS-005 finding depending on scan order. All 9 rules now run patterns
  through stateless helpers (`firstMatch`/`matches`/`allMatches`) — the shared
  pattern objects are never mutated. Regression-tested.
- **`--no-color` was a no-op.** Color support was captured at import time,
  before the flag set `process.env.NO_COLOR`. Now resolved at render time.
- **Duplicate findings for one blob.** A run of hex characters is also valid
  base64; the same span produced two identical findings. Overlapping blob
  spans are now deduplicated.
- **`--ai-timeout abc` armed an instant abort.** Non-numeric, zero and negative
  values are rejected with a usage error (exit 2) instead of silently breaking
  the AI layer.
- **Multi-line YAML descriptions were dropped.** Block scalars (`|`, `|-`, `>`,
  `>-`) now join into one value — the main description surface of real SKILL.md
  files.
- **UTF-8 BOM broke frontmatter detection.** Files saved by Windows editors now
  parse correctly.
- **Misleading SS-007 evidence.** Evidence now quotes the matched data-surface
  itself instead of a synthetic compound that could fall back to unrelated text.
- **CI self-scan gate was self-defeating.** Scanning poisoned fixtures with
  `--fail-on high` always exited 1 (red CI). The gate is now two-sided: clean
  fixtures must pass (exit 0), poisoned fixtures must be caught (exit 1 expected).

### Changed
- `parseArgs` is now exported and pure (throws `CliError` instead of exiting) —
  CLI usage rules are unit-tested.
- Importing the CLI module has zero side effects (auto-run guarded by entry
  detection); previously importing it triggered a scan.
- `--version` reads the version from `package.json` instead of a hard-coded
  string.
- Removed dead code (`aiCanRaise`, unused timer) — no public API change.
- TypeScript is stricter: `noUncheckedIndexedAccess`, `noImplicitOverride`,
  `noFallthroughCasesInSwitch`, with all index accesses explicitly guarded.

### Added
- ESLint 9 (flat config) with type-checked `typescript-eslint`, enforced at
  `--max-warnings 0` in CI; `npm run lint` and `npm run typecheck` scripts.
- `test/determinism.test.ts`: same input scanned repeatedly and in different
  orders must produce identical findings.
- `test/cli.test.ts`: argument-parsing contract, including the timeout guard.
- Parser edge-case tests: block scalars, BOM, CRLF, quoted list items.
- Dashboard `POST /api/scan` rejects inputs over 400,000 characters (HTTP 413).
- CI installs with `npm ci` for reproducible builds, and runs lint + typecheck.
- This changelog, `CONTRIBUTING.md` and `SECURITY.md`.

## [0.1.0] — 2026-10-20

Initial public release.

### Added
- 9 deterministic static rules (SS-001…SS-009) covering hidden instructions,
  exfiltration endpoints, credential access, destructive commands, obfuscation,
  cross-tool shadowing, surveillance, insecure MCP configs and deceptive
  metadata — each mapped to OWASP LLM Top 10 (2026), Agentic Skills Top 10 and
  OWASP MCP Top 10.
- Open-weight semantic layer: any local OpenAI-compatible runtime (Ollama with
  Gemma by default, llama.cpp server, LM Studio, vLLM). Nothing leaves the
  machine; graceful degradation to static-only when no runtime answers.
- Zero runtime dependencies; Node.js >= 20; MIT.
- CLI with terminal / JSON / Markdown output and `--fail-on` CI gate.
- Local Next.js dashboard (apps/dashboard) on port 3210.
- Sample gallery: clean + deliberately poisoned fixtures used as regression tests.
- 56 tests across 5 suites, CI matrix on Node 20/22/24 with dogfooding self-scan.

[Unreleased]: https://github.com/Ulk0r0/skillsentry/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Ulk0r0/skillsentry/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Ulk0r0/skillsentry/releases/tag/v0.1.0
