#!/usr/bin/env node
/**
 * SkillSentry CLI — zero runtime dependencies.
 *
 *   skillsentry [paths...] [options]
 *
 * Examples:
 *   skillsentry .                          scan cwd for SKILL.md + MCP configs
 *   skillsentry skills/ --json             JSON output (pipe-friendly)
 *   skillsentry . --fail-on high           exit 1 when high+ findings exist (CI)
 *   skillsentry . --no-ai                  static rules only
 *   skillsentry . --model llama3.2:3b      pick another open-weight model
 */
import { scanPaths } from './scanner.js';
import { renderTerminal, renderMarkdown, renderJson, exitCodeFor } from './report.js';
import { renderSarif } from './report-sarif.js';
import {
  diffResults,
  exitCodeForDiff,
  renderDiffTerminal,
  renderDiffJson
} from './diff.js';
import { DEFAULT_AI_BASE_URL, DEFAULT_MODEL } from './ai.js';
import type { Severity } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import { createRequire } from 'node:module';
import { realpathSync, writeSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

interface CliArgs {
  paths: string[];
  json: boolean;
  md: boolean;
  sarif: boolean;
  failOn: Severity;
  ai: boolean;
  aiBaseUrl?: string;
  model?: string;
  aiTimeoutMs?: number;
  verbose: boolean;
}

/** Usage error thrown by parseArgs; main() converts it to exit code 2. */
export class CliError extends Error {}

const VERSION = (() => {
  try {
    const req = createRequire(import.meta.url);
    const pkg = req('../package.json') as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

const USAGE = `SkillSentry v${VERSION} — local-first security scanner for AI agent skills (SKILL.md)
and MCP server configs. Static rules + open-weight model review, zero dependencies.

USAGE
  skillsentry [paths...] [options]
  skillsentry diff <old> <new> [options]   what changed between two snapshots?

OPTIONS
  --json               JSON output
  --md                 Markdown output
  --sarif              SARIF 2.1.0 output (GitHub Code Scanning ready)
  --fail-on <sev>      exit 1 if findings at/above severity (info|low|medium|high|critical). Default: high
  --no-ai              skip the open-weight model layer (static rules only)
  --ai                 force the AI layer even if the probe is slow
  --ollama-url <url>   OpenAI-compatible base URL. Default: ${DEFAULT_AI_BASE_URL}
  --model <id>         open-weight model id. Default: ${DEFAULT_MODEL}
  --ai-timeout <ms>    per-target AI timeout (default 20000)
  --verbose            diagnostics to stderr
  --no-color           disable ANSI colors
  -h, --help           this help
  -V, --version        version

DIFF (rug-pull detection)
  skillsentry diff ~/skills-backup/ ~/.claude/skills/ --fail-on high
  Compares two scans semantically (by skill/config name, so the snapshots can
  live in different directories) and exits 1 when the NEW snapshot introduces
  findings at or above the threshold — an updated skill that turns poisonous.

EXAMPLES
  skillsentry .                          # scan cwd
  skillsentry skills/ mcp/ --json        # scan two dirs, JSON out
  skillsentry . --sarif > results.sarif  # upload to GitHub Code Scanning
  skillsentry . --fail-on medium         # CI gate at medium
  skillsentry . --no-ai                  # deterministic offline mode
`;

const DIFF_USAGE = `skillsentry diff <old> <new> — compare two snapshots and report what changed.

Run 'skillsentry --help' for the full option list.
`;

/**
 * Exported (pure) for tests: argument parsing without side effects.
 * Invalid usage throws `CliError` instead of writing/exiting.
 */
export function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    paths: [],
    json: false,
    md: false,
    sarif: false,
    failOn: 'high',
    ai: true,
    aiBaseUrl: undefined,
    model: undefined,
    aiTimeoutMs: undefined,
    verbose: false
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    switch (a) {
      case '--json': args.json = true; break;
      case '--md': case '--markdown': args.md = true; break;
      case '--sarif': args.sarif = true; break;
      case '--fail-on': {
        const v = argv[++i] ?? '';
        if (!SEVERITY_ORDER.includes(v as Severity)) {
          throw new CliError(`--fail-on must be one of ${SEVERITY_ORDER.join('|')}`);
        }
        args.failOn = v as Severity;
        break;
      }
      case '--no-ai': args.ai = false; break;
      case '--ai': args.ai = true; break;
      case '--ollama-url': case '--ai-url': case '--openai-base-url': args.aiBaseUrl = argv[++i] ?? undefined; break;
      case '--model': args.model = argv[++i] ?? undefined; break;
      case '--ai-timeout': {
        const n = Number(argv[++i] ?? 20000);
        // A NaN/0/negative timeout would arm an AbortController that fires
        // instantly, silently breaking the AI layer.
        if (!Number.isFinite(n) || n <= 0) throw new CliError('--ai-timeout must be a positive number of milliseconds');
        args.aiTimeoutMs = n;
        break;
      }
      case '--verbose': args.verbose = true; break;
      case '--no-color': process.env.NO_COLOR = '1'; break;
      case '-h': case '--help': { writeSync(1, USAGE); process.exit(0); break; }
      case '-V': case '--version': { writeSync(1, `skillsentry ${VERSION}\n`); process.exit(0); break; }
      default:
        if (a.startsWith('--')) throw new CliError(`unknown option: ${a}`);
        args.paths.push(a);
    }
  }
  if (args.paths.length === 0) args.paths.push('.');
  const formats = [args.json, args.md, args.sarif].filter(Boolean).length;
  if (formats > 1) throw new CliError('choose a single output format: --json, --md or --sarif');
  return args;
}

function fail(msg: string): never {
  process.stderr.write(`skillsentry: ${msg}\n`);
  process.exit(2);
}

/** Arguments accepted by the `skillsentry diff <old> <new>` subcommand. */
export interface DiffArgs {
  oldPath: string;
  newPath: string;
  json: boolean;
  failOn: Severity;
  ai: boolean;
  aiBaseUrl?: string;
  model?: string;
  aiTimeoutMs?: number;
  verbose: boolean;
}

/**
 * Exported (pure) for tests: parses everything after the `diff` keyword.
 * Requires exactly two positional snapshot paths; flags are the shared scan
 * options minus output selectors other than --json.
 */
export function parseDiffArgs(argv: string[]): DiffArgs {
  const args: DiffArgs = {
    oldPath: '',
    newPath: '',
    json: false,
    failOn: 'high',
    ai: true,
    aiBaseUrl: undefined,
    model: undefined,
    aiTimeoutMs: undefined,
    verbose: false
  };
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    switch (a) {
      case '--json': args.json = true; break;
      case '--md': case '--markdown': case '--sarif':
        throw new CliError('diff supports --json only (diff of --md/--sarif is not defined)');
      case '--fail-on': {
        const v = argv[++i] ?? '';
        if (!SEVERITY_ORDER.includes(v as Severity)) {
          throw new CliError(`--fail-on must be one of ${SEVERITY_ORDER.join('|')}`);
        }
        args.failOn = v as Severity;
        break;
      }
      case '--no-ai': args.ai = false; break;
      case '--ai': args.ai = true; break;
      case '--ollama-url': case '--ai-url': case '--openai-base-url': args.aiBaseUrl = argv[++i] ?? undefined; break;
      case '--model': args.model = argv[++i] ?? undefined; break;
      case '--ai-timeout': {
        const n = Number(argv[++i] ?? 20000);
        if (!Number.isFinite(n) || n <= 0) throw new CliError('--ai-timeout must be a positive number of milliseconds');
        args.aiTimeoutMs = n;
        break;
      }
      case '--verbose': args.verbose = true; break;
      case '--no-color': process.env.NO_COLOR = '1'; break;
      default:
        if (a.startsWith('--')) throw new CliError(`unknown option: ${a}`);
        positional.push(a);
    }
  }
  if (positional.length !== 2) {
    throw new CliError('diff requires exactly two snapshot paths: skillsentry diff <old> <new>');
  }
  args.oldPath = positional[0] ?? '';
  args.newPath = positional[1] ?? '';
  return args;
}

async function diffMain(argv: string[]): Promise<void> {
  let d: DiffArgs;
  try {
    d = parseDiffArgs(argv);
  } catch (err) {
    fail(err instanceof CliError ? `${err.message}\n\n${DIFF_USAGE}` : `fatal: ${String(err)}`);
  }
  const log = d.verbose ? (m: string) => process.stderr.write(`${m}\n`) : undefined;
  const scanOpts = {
    ai: d.ai,
    openaiBaseUrl: d.aiBaseUrl,
    model: d.model,
    aiTimeoutMs: d.aiTimeoutMs,
    log
  };
  // Sequential scans keep memory flat and logs ordered; determinism means
  // order of the two scans cannot change the outcome (tested).
  const oldResult = await scanPaths([d.oldPath], scanOpts);
  const newResult = await scanPaths([d.newPath], scanOpts);
  const diff = diffResults(oldResult, newResult);

  process.stdout.write(d.json ? renderDiffJson(diff) + '\n' : renderDiffTerminal(diff));
  process.exitCode = exitCodeForDiff(diff, d.failOn);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv[0] === 'diff') {
    await diffMain(argv.slice(1));
    return;
  }

  let args: CliArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    fail(err instanceof CliError ? `${err.message}\n\n${USAGE}` : `fatal: ${String(err)}`);
  }
  const log = args.verbose ? (m: string) => process.stderr.write(`${m}\n`) : undefined;

  const result = await scanPaths(args.paths, {
    ai: args.ai,
    openaiBaseUrl: args.aiBaseUrl,
    model: args.model,
    aiTimeoutMs: args.aiTimeoutMs,
    failOn: args.failOn,
    log
  });

  if (args.json) {
    process.stdout.write(renderJson(result) + '\n');
  } else if (args.md) {
    process.stdout.write(renderMarkdown(result) + '\n');
  } else if (args.sarif) {
    process.stdout.write(renderSarif(result, { toolVersion: VERSION }) + '\n');
  } else {
    process.stdout.write(renderTerminal(result));
  }

  // Never call process.exit() after writing a large payload to stdout — it
  // truncates pending pipe writes. Set the exit code and exit naturally.
  process.exitCode = exitCodeFor(result, args.failOn);
}

// Only auto-run when this file IS the process entry (direct `node cli.js` or
// the installed bin). Importing the module (tests, library reuse) must have
// zero side effects — previously importing cli.ts triggered a real scan.
const isEntry = (() => {
  try {
    return process.argv[1] !== undefined && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
})();

if (isEntry) {
  main().catch((err) => {
    process.stderr.write(`skillsentry: fatal: ${err instanceof Error ? err.stack : String(err)}\n`);
    process.exit(2);
  });
}
