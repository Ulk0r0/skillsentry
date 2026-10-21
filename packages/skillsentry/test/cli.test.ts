import { describe, it, expect } from 'vitest';
import { parseArgs, CliError } from '../src/cli.js';

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
});
