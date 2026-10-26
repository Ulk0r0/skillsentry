import { describe, it, expect } from 'vitest';
import { parseArgs, parseDiffArgs, CliError, stdinTargetPath } from '../src/cli.js';
import { scanText } from '../src/scanner.js';

/**
 * The CLI argument parser is pure (throws CliError instead of exiting), so
 * usage rules are unit-testable without spawning a process.
 */

describe('parseArgs', () => {
  it('defaults to scanning cwd with terminal output and high threshold', () => {
    const a = parseArgs([]);
    expect(a.paths).toEqual(['.']);
    expect(a.json).toBe(false);
    expect(a.md).toBe(false);
    expect(a.failOn).toBe('high');
    expect(a.ai).toBe(true);
    expect(a.aiTimeoutMs).toBeUndefined();
  });

  it('collects paths and toggles output modes', () => {
    const a = parseArgs(['skills/', 'mcp/', '--json', '--no-ai', '--verbose']);
    expect(a.paths).toEqual(['skills/', 'mcp/']);
    expect(a.json).toBe(true);
    expect(a.ai).toBe(false);
    expect(a.verbose).toBe(true);
  });

  it('accepts --md alias and explicit fail-on severity', () => {
    const a = parseArgs(['--markdown', '--fail-on', 'medium']);
    expect(a.md).toBe(true);
    expect(a.failOn).toBe('medium');
  });

  it('parses a valid numeric --ai-timeout', () => {
    const a = parseArgs(['--ai-timeout', '5000']);
    expect(a.aiTimeoutMs).toBe(5000);
  });

  it('rejects non-numeric, zero and negative --ai-timeout (NaN would abort instantly)', () => {
    for (const bad of ['abc', '0', '-5']) {
      expect(() => parseArgs(['--ai-timeout', bad])).toThrow(CliError);
    }
  });

  it('rejects invalid --fail-on values', () => {
    expect(() => parseArgs(['--fail-on', 'apocalyptic'])).toThrow(CliError);
  });

  it('rejects unknown options', () => {
    expect(() => parseArgs(['--totally-real-flag'])).toThrow(CliError);
  });

  it('treats non-flag arguments as paths', () => {
    const a = parseArgs(['samples', '-']);
    expect(a.paths).toEqual(['samples', '-']);
  });

  it('rejects combining output formats (--json + --md + --sarif)', () => {
    expect(() => parseArgs(['--json', '--sarif'])).toThrow(CliError);
    expect(() => parseArgs(['--md', '--json'])).toThrow(CliError);
    expect(() => parseArgs(['--sarif'])).not.toThrow();
  });
});

describe('parseDiffArgs (skillsentry diff <old> <new>)', () => {
  it('takes exactly two positional snapshot paths with sane defaults', () => {
    const a = parseDiffArgs(['/backup/skills', '/current/skills']);
    expect(a.oldPath).toBe('/backup/skills');
    expect(a.newPath).toBe('/current/skills');
    expect(a.failOn).toBe('high');
    expect(a.json).toBe(false);
    expect(a.ai).toBe(true);
  });

  it('accepts the shared scan flags', () => {
    const a = parseDiffArgs(['--json', '--fail-on', 'medium', '--no-ai', '--verbose', 'old', 'new']);
    expect(a.json).toBe(true);
    expect(a.failOn).toBe('medium');
    expect(a.ai).toBe(false);
    expect(a.verbose).toBe(true);
  });

  it('rejects one or three positionals', () => {
    expect(() => parseDiffArgs(['only-one'])).toThrow(CliError);
    expect(() => parseDiffArgs(['a', 'b', 'c'])).toThrow(CliError);
    expect(() => parseDiffArgs([])).toThrow(CliError);
  });

  it('rejects --md/--sarif (diff defines only pretty and --json output)', () => {
    expect(() => parseDiffArgs(['--md', 'a', 'b'])).toThrow(CliError);
    expect(() => parseDiffArgs(['--sarif', 'a', 'b'])).toThrow(CliError);
  });

  it('rejects invalid --fail-on and unknown options', () => {
    expect(() => parseDiffArgs(['--fail-on', 'cosmic', 'a', 'b'])).toThrow(CliError);
    expect(() => parseDiffArgs(['--wat', 'a', 'b'])).toThrow(CliError);
  });
});

describe('parseArgs — flag value requirements & new flags', () => {
  it('--ai carries force semantics: skip the probe, attempt the endpoint anyway', () => {
    const a = parseArgs(['--ai']);
    expect(a.ai).toBe(true);
    expect(a.aiForce).toBe(true);
  });

  it('a default invocation does not force the AI layer', () => {
    const a = parseArgs(['.']);
    expect(a.ai).toBe(true);
    expect(a.aiForce).toBe(false);
  });

  it('--no-ai followed by --ai ends up forced-on (last flag wins, honestly)', () => {
    const a = parseArgs(['--no-ai', '--ai']);
    expect(a.ai).toBe(true);
    expect(a.aiForce).toBe(true);
  });

  it('--stdin parses alone but rejects paths', () => {
    expect(parseArgs(['--stdin']).stdin).toBe(true);
    expect(() => parseArgs(['--stdin', 'skills/'])).toThrow(CliError);
  });

  it('diff rejects --stdin (it compares two snapshot paths)', () => {
    expect(() => parseDiffArgs(['--stdin', 'a', 'b'])).toThrow(CliError);
  });

  it('value-taking flags fail loudly on a missing value instead of silently defaulting', () => {
    expect(() => parseArgs(['--model'])).toThrow(CliError);
    expect(() => parseArgs(['--model', ''])).toThrow(CliError);
    expect(() => parseArgs(['--ollama-url'])).toThrow(CliError);
    expect(() => parseArgs(['--ollama-url', ''])).toThrow(CliError);
    expect(() => parseArgs(['--ai-timeout'])).toThrow(CliError);
    expect(() => parseArgs(['--fail-on'])).toThrow(CliError);
    expect(() => parseDiffArgs(['--model'])).toThrow(CliError);
    expect(() => parseDiffArgs(['--fail-on'])).toThrow(CliError);
    // valid values still parse
    expect(parseArgs(['--model', 'gemma3:4b']).model).toBe('gemma3:4b');
    expect(parseArgs(['--ollama-url', 'http://localhost:1234/v1']).aiBaseUrl).toBe('http://localhost:1234/v1');
    expect(parseArgs(['--fail-on', 'low']).failOn).toBe('low');
  });
});

describe('stdinTargetPath — piped-payload dispatch', () => {
  it('routes JSON MCP configs to the structured mcp-config parser', () => {
    expect(stdinTargetPath('{"mcpServers":{"x":{"command":"node"}}}')).toBe('stdin/claude_desktop_config.json');
  });

  it('keeps everything else on the skill-markdown best-effort path', () => {
    // VS Code-style "servers" and flat fallbacks stay best effort — only the
    // documented Claude Desktop shape switches parser.
    expect(stdinTargetPath('{"servers":{"x":{"command":"node"}}}')).toBe('stdin/SKILL.md');
    expect(stdinTargetPath('---\nname: demo\n---\nbody')).toBe('stdin/SKILL.md');
    expect(stdinTargetPath('not json at all')).toBe('stdin/SKILL.md');
    expect(stdinTargetPath('["array json"]')).toBe('stdin/SKILL.md');
  });

  it('synthetic stdin paths resolve to the right parser and a readable name', async () => {
    const mcpJson = '{"mcpServers":{"x":{"command":"node","args":["a.js"]}}}';
    const mcp = await scanText(stdinTargetPath(mcpJson), mcpJson, { ai: false as const });
    expect(mcp.kind).toBe('mcp-config');
    expect(mcp.name).toBe('claude_desktop_config.json');

    const skill = await scanText(stdinTargetPath('# doc'), '# doc\nplain body text', { ai: false as const });
    expect(skill.kind).toBe('skill-md');
    expect(skill.name).toBe('stdin');
  });
});
