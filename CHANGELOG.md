# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] — 2026-10-21

Detection breadth and governance release: two new static rules (RCE
one-liners, typosquatting), inline suppressions with a mandatory reason,
property-based robustness tests, and the scanner now watches its own source
in GitHub Code Scanning. Still zero runtime dependencies (fast-check is a
dev-only dependency); the scan API is additive only.

### Added
- **SS-010 — Remote-code-execution one-liners** (`critical`). Download-and-
  execute primitives in agent-readable text or MCP command lines: `curl|bash`
  / `wget|sh` pipes (including through `sudo`), PowerShell `iwr|irm → iex`
  chains, process/command substitution (`bash <(curl …)`, `sh -c "$(curl …)"`),
  download + `chmod +x` staging, and `eval`/`exec` of base64-decoded payloads
  (JS `atob`, Python `base64.b64decode`, Node `Buffer.from(…, 'base64')`).
  SS-004 covered destructive commands already spelled out; SS-002 covered
  data movement — "fetch and run" was the uncovered highest-leverage primitive.
- **SS-011 — Typosquatting / installs from non-official sources** (`high`).
  Deterministic, offline supply-chain checks on install lines
  (`npm/pnpm/yarn/bun install|add`, `npx/pnpx/bunx`, `pip/uv install`) and
  MCP commands: package names within Damerau-Levenshtein distance 2 of a
  reviewed set of ~40 popular npm/PyPI packages (bounded, early-exit
  implementation exported as `boundedDistance`), direct-URL/`git+` installs,
  and `--registry` / `--index-url` / `--extra-index-url` overrides away from
  npmjs.org / pypi.org. Trailing prose punctuation is stripped before
  comparing names ("install numpy." was a distance-1 false positive).
- **Inline suppressions with a mandatory reason** — the ESLint escape hatch,
  made explicit for security findings: `<!-- skillsentry-ignore SS-003
  SS-007: reason -->`. A comment without at least one valid rule id or
  without a reason is ignored (no blank checks). Suppression is file-level
  and never silent: suppressed findings stay in the report (`suppressed` in
  JSON, one audit line in terminal and Markdown renderers) with the winning
  reason, while scoring, verdict, exit code and diff use only kept findings.
  Pure engine (`parseSuppressions`/`applySuppressions`) exported for library
  use.
- **Property-based tests** (`test/properties.test.ts`, fast-check as a
  dev-only dependency): for every input — the parsers never throw on
  arbitrary text (300 runs each), `stripJsonc` round-trips any valid JSON
  value (including strings full of `//` and `/*`), `aggregateRisk` stays in
  0–100 with a known verdict and `clean` on empty, critical findings always
  yield `dangerous`, and suppression comments always fully cover their named
  rules.
- **Own-source Code Scanning upload.** CI (Node 22 lane) generates a SARIF
  report over `packages/` + `apps/` via
  `packages/skillsentry/scripts/self-sarif.mjs` and uploads it with
  `github/codeql-action/upload-sarif@v3` (`security-events: write`). The
  intentionally poisoned `samples/` are deliberately excluded — they are
  attack fixtures, not code. Any future poisoned instruction in the
  scanner's own source becomes a visible GitHub alert.
- The rule registry grows from 9 to 11 rules; `ALL_RULES` ids are asserted
  in order by a unit test.

### Fixed
- **SS-005 no longer flags the suppression mechanism.** The official
  `<!-- skillsentry-ignore … -->` comment contains the word "ignore", which
  tripped the hidden-comment directive heuristic — the tool would flag its
  own escape hatch. Declared, reasoned ignore comments are now exempt from
  the hidden-channel rule (they remain visible, reasoned and audited).
- **ANSI escapes no longer pollute piped output.** Colors now follow the
  standard UNIX contract: enabled only when stdout is a TTY. Piping into
  `tee`, a file or a CI log stays escape-free; `FORCE_COLOR=1` opts back in
  (e.g. `skillsentry . | less -R`), and `NO_COLOR` still wins over both.
- **`--verbose` now reports skipped inputs.** Paths that do not exist, are
  unreadable, or are not scan candidates were silently recorded in
  `skipped` without any stderr diagnostic — with `--verbose` each skip is
  logged with its reason.

### Changed
- Tests: 97 → 127 (SS-010 ×5, SS-011 ×4, suppressions ×12, property-based
  invariants ×8, TTY/verbose regression ×2). Measured coverage holds above
  the enforced thresholds.

## [0.3.0] — 2026-10-21

Feature release: rug-pull detection, SARIF 2.1.0 output, JSONC-tolerant
config parsing, enforced coverage and a benchmark harness. Still zero runtime
dependencies; the scan API is additive only.

### Added
- **`skillsentry diff <old> <new>`** — rug-pull detection. Compares two
  snapshots of the same skills/configs semantically (matched by kind + name,
  so the snapshots may live in different directories) and reports added,
  resolved and unchanged findings. Exit code 1 when the NEW snapshot
  introduces findings at or above `--fail-on`: an updated skill that turns
  poisonous fails the gate, a merely reworded one cannot sneak past (findings
  match on rule + surface + severity, not on the attacker's prose).
  `--json` available for machine consumption. Pure diff engine
  (`diffResults`/`exitCodeForDiff`) exported for library use.
- **`--sarif`** — SARIF 2.1.0 output for GitHub Code Scanning
  (`github/codeql-action/upload-sarif`): deduplicated rule metadata with
  remediation and standards help URIs, severity→level mapping
  (critical/high→error, medium→warning, low/info→note), repo-relative
  artifact URIs via the `root` option. Renderer exported as `renderSarif`.
- **JSONC tolerance for MCP configs.** VS Code and Claude Desktop configs
  are frequently commented. A string-aware stripper (`stripJsonc`) removes
  `//` and block comments plus trailing commas while preserving URLs and
  quoted text verbatim; parsing falls back to it before declaring a config
  unparseable — previously, commented configs were scanned as opaque text
  and comment prose could trigger text rules (false positives).
- **Enforced coverage.** `@vitest/coverage-v8` (dev-only) with CI thresholds:
  85% lines/statements/functions, 75% branches — measured today at 90/79/93
  and only ever raised.
- **`npm run bench`** — fixed-workload benchmark of the static engine
  (sample gallery, AI off): median 4.1 ms/run, ~2.4k files/s, comparable
  across commits.
- Output-format guard: `--json`, `--md` and `--sarif` are mutually
  exclusive; combining them is now a usage error instead of a silent
  precedence pick.

### Changed
- **Verdict policy: a report with findings is never `CLEAN`.** Any
  low-or-above finding now yields at least `suspicious`; previously a single
  low finding produced `CLEAN risk 16/100` with the finding still listed —
  a badge contradicting its own evidence. Info-only reports stay clean
  (no shipped rule emits info today).

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
