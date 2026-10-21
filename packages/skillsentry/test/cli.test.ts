import { describe, it, expect } from 'vitest';
import { parseArgs, parseDiffArgs, CliError } from '../src/cli.js';

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
