/**
 * Text helpers: ANSI output, evidence extraction and a minimal frontmatter
 * parser. Zero runtime dependencies — SkillSentry itself must not become a
 * supply-chain liability.
 */

import type { Severity } from '../types.js';

// ---------------------------------------------------------------- ANSI ----

/**
 * Color support is resolved at render time, not at import time: the CLI's
 * `--no-color` flag mutates `process.env.NO_COLOR` after modules load, and
 * capturing the value here would silently break the flag.
 */
function colorEnabled(): boolean {
  return process.env.NO_COLOR == null;
}

function wrap(open: string, close: string) {
  // Per-attribute reset (e.g. bold ends with 22, not the blanket 0) — valid
  // ANSI and survives nested styling.
  return (s: string) => (colorEnabled() ? `\u001B[${open}m${s}\u001B[${close}m` : s);
}

export const ansi = {
  bold: wrap('1', '22'),
  dim: wrap('2', '22'),
  red: wrap('31', '39'),
  green: wrap('32', '39'),
  yellow: wrap('33', '39'),
  blue: wrap('34', '39'),
  magenta: wrap('35', '39'),
  cyan: wrap('36', '39')
};

export const severityColor: Record<Severity, (s: string) => string> = {
  info: ansi.blue,
  low: ansi.cyan,
  medium: ansi.yellow,
  high: ansi.magenta,
  critical: ansi.red
};

// ----------------------------------------------------------- evidence ----

/** Collapse whitespace so quoted evidence stays on one readable line. */
export function squash(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

/**
 * Extract a short quoted snippet around the first match of `needle` inside
 * `text`, with a bounded window on each side. Never throws.
 */
export function evidenceFor(text: string, needle: string, window = 90): string {
  const idx = text.indexOf(needle);
  const flat = squash(text);
  if (idx === -1) return flat.slice(0, window * 2);
  const start = Math.max(0, idx - window);
  const end = Math.min(text.length, idx + needle.length + window);
  const snippet = squash(text.slice(start, end));
  return (start > 0 ? '…' : '') + snippet + (end < text.length ? '…' : '');
}

// -------------------------------------------------------- frontmatter ----

export interface Frontmatter {
  data: Record<string, string | string[]>;
  body: string;
  raw: string;
}

/**
 * Parse the `---\n...\n---` frontmatter used by SKILL.md (Agent Skills spec).
 * Deliberately minimal: scalar values and flat lists. Unknown shapes fall
 * back to raw strings — parsing must never crash a scan.
 */
export function parseFrontmatter(input: string): Frontmatter {
  // Strip a UTF-8 BOM so files saved by Windows editors still get their
  // frontmatter recognized.
  const raw = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  const m = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)([\s\S]*)$/.exec(raw);
  if (!m || m[1] === undefined || m[2] === undefined) return { data: {}, body: raw, raw };
  const fm = m[1];
  const body = m[2];
  const data: Record<string, string | string[]> = {};
  let currentKey: string | null = null;
  let blockOpener: string | null = null; // '|' or '>' block scalar in progress
  for (const line of fm.split(/\r?\n/)) {
    if (!line.trim() || line.trim().startsWith('#')) continue;

    // Continuation of a YAML block scalar (| or >): any line indented deeper
    // than the key keeps feeding the value, verbatim for | and folded for >.
    if (blockOpener && currentKey && /^\s+\S/.test(line)) {
      const prev = data[currentKey];
      const isFirstLine = typeof prev === 'string' && /^(?:\|-?|>-?)$/.test(prev);
      data[currentKey] = isFirstLine ? line.trim() : `${typeof prev === 'string' ? prev : ''} ${line.trim()}`.trim();
      continue;
    }
    blockOpener = null;

    const listItem = /^\s+-\s*(.+)$/.exec(line);
    if (listItem && currentKey && listItem[1] !== undefined) {
      const arr = Array.isArray(data[currentKey]) ? (data[currentKey] as string[]) : [];
      arr.push(stripQuotes(listItem[1].trim()));
      data[currentKey] = arr;
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+)\s*:\s*(.*)$/.exec(line);
    if (kv && kv[1] !== undefined) {
      currentKey = kv[1];
      const value = (kv[2] ?? '').trim();
      if (value === '') continue; // possibly a list follows
      if (value === '|' || value === '|-' || value === '>' || value === '>-') {
        blockOpener = value[0] ?? null; // multi-line value; collect indented lines below
        data[currentKey] = value;
        continue;
      }
      data[currentKey] = stripQuotes(value);
    }
  }
  // A block scalar that collected nothing must not stay as a literal "|".
  for (const [k, v] of Object.entries(data)) {
    if (v === '|' || v === '|-' || v === '>' || v === '>-') data[k] = '';
  }
  return { data, body, raw };
}

function stripQuotes(s: string): string {
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

/**
 * Case-insensitive regex builder that is safe against user input (only
 * our code supplies patterns here).
 */
export function rx(pattern: string, flags = 'i'): RegExp {
  return new RegExp(pattern, flags);
}

// ---------------------------------------------------------- regex state ----

/**
 * Module-level regexes are shared across scans; stateful APIs (`exec`,
 * `test` on a `/g` pattern) leak `lastIndex` between files and make results
 * depend on scan order. Rules MUST go through this helper: it runs the
 * pattern against a fresh clone, so the shared object is never mutated.
 */
export function firstMatch(re: RegExp, text: string): RegExpExecArray | null {
  const local = new RegExp(re.source, re.flags);
  return local.exec(text);
}

/** `firstMatch` for boolean checks — never mutates the shared pattern. */
export function matches(re: RegExp, text: string): boolean {
  return firstMatch(re, text) !== null;
}

/**
 * Iterate all matches of a global pattern without touching its state.
 * (`String.matchAll` already clones internally; this exists so call sites
 * state the invariant explicitly and stay uniform.)
 */
export function allMatches(re: RegExp, text: string): RegExpMatchArray[] {
  return [...text.matchAll(new RegExp(re.source, re.flags))];
}
