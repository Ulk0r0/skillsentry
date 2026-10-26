import type { Rule } from './rule.js';
import { AST, LLM, MCP } from '../mapping.js';
import { evidenceFor, firstMatch } from '../util/text.js';

/**
 * SS-011 — Typosquatting and installs from non-official sources.
 *
 * A skill that instructs (or configures) the installation of a package is a
 * supply-chain decision made on the agent's behalf. Three signals matter:
 *   1. the package name is a near-miss of a popular one (typosquat);
 *   2. the package comes from a direct URL / git repo instead of the registry;
 *   3. the install points at a non-official registry or index.
 * All three are deterministic text checks — no network, no nameserver lookups.
 */

/** Widely-installed packages (npm + PyPI). Short, reviewed, deterministic. */
const POPULAR: ReadonlySet<string> = new Set([
  // npm
  'express', 'react', 'vue', 'angular', 'lodash', 'axios', 'request', 'chalk',
  'commander', 'typescript', 'webpack', 'eslint', 'jest', 'mocha', 'moment',
  'underscore', 'async', 'debug', 'colors', 'uuid', 'yaml', 'dotenv', 'next',
  'node-fetch', 'cross-env', 'ts-node', 'socket.io', 'react-dom', 'vite',
  // PyPI
  'requests', 'flask', 'django', 'numpy', 'pandas', 'scipy', 'matplotlib',
  'pytest', 'setuptools', 'boto3', 'tensorflow', 'torch', 'scrapy', 'click',
  'pyyaml', 'pillow', 'sqlalchemy', 'fastapi', 'httpx', 'aiohttp'
]);

const OFFICIAL_REGISTRIES = /(?:^|\/\/|@)(?:registry\.npmjs\.org|pypi\.org|files\.pythonhosted\.org)/i;

/**
 * Bounded Damerau-Levenshtein distance (OSA variant — transpositions count
 * as one edit). Returns a value > max as soon as the answer can no longer be
 * within budget, so typosquat checks against ~40 popular names stay cheap
 * and fully deterministic.
 */
export function boundedDistance(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const la = a.length;
  const lb = b.length;
  // dp[i][j] = distance between a[0..i) and b[0..j)
  let prev2: number[] = [];
  let prev: number[] = new Array<number>(lb + 1);
  let curr: number[] = new Array<number>(lb + 1);
  for (let j = 0; j <= lb; j++) prev[j] = j;
  for (let i = 1; i <= la; i++) {
    curr[0] = i;
    let rowMin: number = curr[0] ?? 0;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let d = Math.min(
        (prev[j] ?? 0) + 1,      // deletion
        (curr[j - 1] ?? 0) + 1,  // insertion
        (prev[j - 1] ?? 0) + cost // substitution
      );
      if (
        i > 1 && j > 1 &&
        a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]
      ) {
        d = Math.min(d, (prev2[j - 2] ?? 0) + 1); // transposition
      }
      curr[j] = d;
      if (d < rowMin) rowMin = d;
    }
    if (rowMin > max) return max + 1; // early exit: whole row already over budget
    prev2 = prev;
    prev = curr;
    curr = new Array<number>(lb + 1);
  }
  return prev[lb] ?? max + 1;
}

/** True when `pkg` is a near-miss (1–2 edits) of a popular package. */
function typosquatOf(pkg: string): string | null {
  const lower = pkg.toLowerCase();
  if (POPULAR.has(lower)) return null; // exact popular name: legitimate
  if (lower.length < 3) return null;
  for (const popular of POPULAR) {
    const d = boundedDistance(lower, popular, 2);
    if (d >= 1 && d <= 2) return popular;
  }
  return null;
}

/** Strip version suffixes and scope-internal '@' from an npm-style spec. */
function normalizeNpmSpec(spec: string): string {
  const s = spec.trim();
  // Scoped package: keep "@scope/name", drop a trailing "@version".
  if (s.startsWith('@')) {
    const slash = s.indexOf('/');
    if (slash > 0) {
      const tail = s.slice(slash + 1);
      const at = tail.indexOf('@');
      return at > 0 ? '@' + s.slice(1, slash + 1) + tail.slice(0, at) : s;
    }
  }
  const at = s.indexOf('@');
  return at > 0 ? s.slice(0, at) : s;
}

/** Package-ish tokens from the argument list of an install/run command. */
function packageTokens(arglist: string): string[] {
  const tokens: string[] = [];
  for (const raw of arglist.split(/\s+/)) {
    // Trailing punctuation from prose ("install numpy.") must not leak into
    // the package name — "numpy." would be a distance-1 near-miss of "numpy".
    const t = raw.trim().replace(/[.,;:!?)\]]+$/, '');
    if (!t || t.startsWith('-')) continue; // flags out
    if (/^https?:\/\//i.test(t) || /^git\+/i.test(t)) { tokens.push(t); continue; }
    if (t.includes('/')) { tokens.push(t); continue; } // scoped or git path
    if (/^[\w.-]+$/.test(t)) tokens.push(t);
  }
  return tokens;
}

export const packageInstall: Rule = {
  id: 'SS-011',
  title: 'Typosquatting / package installs from non-official sources',
  description:
    'Installation instructions or MCP commands that pull packages whose names closely mimic popular ones (Damerau-Levenshtein distance ≤ 2), install from a direct URL or git repo instead of the official registry, or point npm/pip at a non-official registry/index. These are the classic supply-chain pivots: the skill author decides what code enters the environment.',
  remediation:
    'Pin exact versions from the official registry (npmjs.org / pypi.org). Double-check near-miss package names character by character, and never override --registry / --index-url to a third-party host inside skill text or MCP commands.',
  severity: 'high',
  score: 8,
  standards: [LLM.supplyChain(), AST.poisoning(), MCP.insecureConfig()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'high' | 'medium'; score?: number }> = [];
    const seen = new Set<string>();
    const push = (needle: string, note: string, severity: 'high' | 'medium', score: number): void => {
      if (seen.has(needle)) return;
      seen.add(needle);
      out.push({ evidence: evidenceFor(surface.text, needle), note, severity, score });
    };

    // (1) + (2) — package names in npm/pnpm/yarn/npx/pip/uv install lines.
    const NPM_INSTALL = /(?:npm\s+(?:install|i|add)|pnpm\s+(?:add|i|install)|yarn\s+(?:add|install)|npx|pnpx|bunx)\s+([^\n;|]+)/gi;
    const PIP_INSTALL = /(?:pip3?|uv)\s+install\s+([^\n;|]+)/gi;
    const specs: string[] = [];
    for (const m of surface.text.matchAll(NPM_INSTALL)) {
      const arglist = m[1];
      if (!arglist) continue;
      for (const tok of packageTokens(arglist)) specs.push(tok);
    }
    for (const m of surface.text.matchAll(PIP_INSTALL)) {
      const arglist = m[1];
      if (!arglist) continue;
      for (const tok of packageTokens(arglist)) specs.push(tok);
    }
    for (const spec of specs) {
      if (/^(?:https?:\/\/|git\+)/i.test(spec)) {
        push(spec, 'Package installed from a direct URL / VCS repo instead of the official registry', 'high', 8);
        continue;
      }
      const name = normalizeNpmSpec(spec);
      const squatter = typosquatOf(name);
      if (squatter) {
        push(
          spec,
          `"${name}" is ${boundedDistance(name.toLowerCase(), squatter, 2)} edit(s) from popular package "${squatter}" — likely typosquatting`,
          'high',
          8
        );
      }
    }

    // (3) — registry / index overrides away from official hosts.
    const REGISTRY = /--registry(?:=|\s+)[^\s]+/gi;
    const INDEX_URL = /(?:--index-url|-i\s+|--extra-index-url)\s+[^\s]+/gi;
    const registry = firstMatch(REGISTRY, surface.text);
    if (registry && !OFFICIAL_REGISTRIES.test(registry[0])) {
      push(registry[0], 'npm install pinned to a non-official registry', 'high', 7.5);
    }
    const index = firstMatch(INDEX_URL, surface.text);
    if (index && !OFFICIAL_REGISTRIES.test(index[0])) {
      const extra = /--extra-index-url/i.test(index[0]);
      push(
        index[0],
        extra
          ? 'pip pointed at an additional (non-official) index — packages may be pulled from an attacker-controlled mirror'
          : 'pip install pinned to a non-official index',
        extra ? 'medium' : 'high',
        extra ? 6.5 : 7.5
      );
    }

    return out;
  }
};
