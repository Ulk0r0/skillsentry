/**
 * Text helpers: ANSI output, evidence extraction and a minimal frontmatter
 * parser. Zero runtime dependencies — SkillSentry itself must not become a
 * supply-chain liability.
 */

import type { Severity } from '../types.js';

// ---------------------------------------------------------------- ANSI ----

const enabled = process.env.NO_COLOR == null;

function wrap(open: string, close: string) {
  return (s: string) => (enabled ? `\u001B[${open}m${s}\u001B[0m` : s);
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
export function parseFrontmatter(raw: string): Frontmatter {
  const m = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)([\s\S]*)$/.exec(raw);
  if (!m) return { data: {}, body: raw, raw };
  const [, fm, body] = m;
  const data: Record<string, string | string[]> = {};
  let currentKey: string | null = null;
  for (const line of fm.split(/\r?\n/)) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const listItem = /^\s+-\s*(.+)$/.exec(line);
    if (listItem && currentKey) {
      const arr = Array.isArray(data[currentKey]) ? (data[currentKey] as string[]) : [];
      arr.push(stripQuotes(listItem[1].trim()));
      data[currentKey] = arr;
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+)\s*:\s*(.*)$/.exec(line);
    if (kv) {
      currentKey = kv[1];
      const value = kv[2].trim();
      if (value === '') continue; // possibly a list follows
      data[currentKey] = stripQuotes(value);
    }
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
