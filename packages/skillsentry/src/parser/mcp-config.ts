import type { ScanSurface, ScanTarget } from '../types.js';

/**
 * Parse MCP server configuration files into scan surfaces.
 *
 * Supported shapes (best effort, never throws):
 * - Claude Desktop: `{ "mcpServers": { "<name>": { "command", "args", "env" } } }`
 * - VS Code / generic: `{ "servers": { "<name>": { "command", "args", "env" } } }`
 * - Flat fallback: `{ "<name>": { "command", ... } }`
 *
 * The config is where an attacker gets code execution on the host, so we scan
 * the exact command lines, arguments and environment variables that will run.
 */

interface ServerEntry {
  name: string;
  command?: unknown;
  args?: unknown;
  env?: unknown;
  url?: unknown;
  [k: string]: unknown;
}

const CONFIG_NAMES = new Set([
  'mcp.json',
  '.mcp.json',
  'claude_desktop_config.json',
  'servers.json',
  'mcp_config.json',
  'settings.json'
]);

export function isMcpConfigFile(fileName: string): boolean {
  return CONFIG_NAMES.has(fileName.toLowerCase());
}

export function parseMcpConfig(filePath: string, raw: string): ScanTarget {
  const surfaces: ScanSurface[] = [];
  let servers: ServerEntry[] = [];
  try {
    const json = JSON.parse(raw) as Record<string, unknown>;
    const bucket =
      (asRecord(json['mcpServers'])) ??
      (asRecord(json['servers'])) ??
      (looksLikeServers(json) ? json : {});
    servers = Object.entries(bucket).map(([name, v]) => ({ name, ...(asRecord(v) ?? {}) }));
  } catch {
    surfaces.push({ location: 'file', text: raw.slice(0, 20000), label: 'unparseable JSON' });
    return { path: filePath, kind: 'mcp-config', name: baseName(filePath), surfaces };
  }

  for (const s of servers) {
    const parts: string[] = [];
    if (typeof s.command === 'string') parts.push(s.command);
    if (Array.isArray(s.args)) parts.push(s.args.map(String).join(' '));
    if (typeof s.url === 'string') parts.push(`url: ${s.url}`);
    if (parts.length) {
      surfaces.push({
        location: `mcpServers.${s.name}`,
        text: parts.join(' '),
        label: s.name
      });
    }
    if (s.env && typeof s.env === 'object') {
      const env = asRecord(s.env) ?? {};
      const envLines = Object.entries(env)
        .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
        .join('\n');
      if (envLines) {
        surfaces.push({ location: `mcpServers.${s.name}.env`, text: envLines, label: s.name });
      }
    }
    // Any other string fields (headers, descriptions) still get scanned.
    const rest = Object.entries(s)
      .filter(([k]) => !['command', 'args', 'env', 'url', 'name'].includes(k))
      .map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)
      .join('\n');
    if (rest.trim()) {
      surfaces.push({ location: `mcpServers.${s.name}.other`, text: rest, label: s.name });
    }
  }

  return { path: filePath, kind: 'mcp-config', name: baseName(filePath), surfaces };
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function looksLikeServers(json: Record<string, unknown>): boolean {
  return Object.values(json).some(
    (v) => v && typeof v === 'object' && !Array.isArray(v) && ('command' in (v as object) || 'url' in (v as object) || 'args' in (v as object))
  );
}

function baseName(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}
