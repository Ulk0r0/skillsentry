import { describe, it, expect } from 'vitest';
import { parseFrontmatter, evidenceFor, squash } from '../src/util/text.js';
import { parseSkillMd, isSkillMdFile } from '../src/parser/skill-md.js';
import { parseMcpConfig, isMcpConfigFile } from '../src/parser/mcp-config.js';

describe('frontmatter parser', () => {
  it('parses scalars, lists and bodies', () => {
    const fm = parseFrontmatter('---\nname: demo\ndescription: A test skill\ntags:\n  - alpha\n  - beta\n---\n# Body\nHello');
    expect(fm.data.name).toBe('demo');
    expect(fm.data.description).toBe('A test skill');
    expect(fm.data.tags).toEqual(['alpha', 'beta']);
    expect(fm.body).toContain('# Body');
  });

  it('never throws on malformed input', () => {
    const fm = parseFrontmatter('no frontmatter here');
    expect(fm.body).toBe('no frontmatter here');
    expect(fm.data).toEqual({});
  });

  it('joins YAML block scalars (| and >) into one description value', () => {
    const fm = parseFrontmatter('---\nname: demo\ndescription: |\n  First line of the pitch.\n  Second line with ~/.ssh mention.\n---\nBody');
    expect(fm.data.description).toBe('First line of the pitch. Second line with ~/.ssh mention.');
    const folded = parseFrontmatter('---\ndescription: >-\n  Folded one.\n  Folded two.\n---\nBody');
    expect(folded.data.description).toBe('Folded one. Folded two.');
  });

  it('an empty block scalar does not leak the "|" opener as content', () => {
    const fm = parseFrontmatter('---\nname: x\ndescription: |\n---\nBody only');
    expect(fm.data.description).toBe('');
  });

  it('strips a UTF-8 BOM so Windows-authored files parse their frontmatter', () => {
    const fm = parseFrontmatter('\uFEFF---\nname: bommed\ndescription: Saved by a Windows editor\n---\nBody');
    expect(fm.data.name).toBe('bommed');
  });

  it('handles CRLF line endings in frontmatter and body', () => {
    const fm = parseFrontmatter('---\r\nname: crlf\ndescription: Windows line endings\r\ntags:\r\n  - one\r\n---\r\nBody line\r\n');
    expect(fm.data.name).toBe('crlf');
    expect(fm.data.description).toBe('Windows line endings');
    expect(fm.data.tags).toEqual(['one']);
    expect(fm.body.startsWith('Body line')).toBe(true);
  });
});

describe('evidence extraction', () => {
  it('squashes whitespace and bounds windows', () => {
    expect(squash('a\n\n  b\tc')).toBe('a b c');
    const ev = evidenceFor('x'.repeat(500), 'needle-not-present');
    expect(ev.length).toBeLessThanOrEqual(200);
  });

  it('extracts a windowed snippet around the needle', () => {
    const ev = evidenceFor('before ' + 'lorem '.repeat(30) + 'TARGET after', 'TARGET');
    expect(ev).toContain('TARGET');
  });
});

describe('SKILL.md parser', () => {
  it('produces description, other-frontmatter and body surfaces', () => {
    const t = parseSkillMd('/x/y/demo/SKILL.md', '---\nname: demo\ndescription: One\nlicense: MIT\n---\nBody text');
    expect(t.kind).toBe('skill-md');
    expect(t.name).toBe('demo');
    expect(t.surfaces.map((s) => s.location)).toEqual(['frontmatter.description', 'frontmatter.other', 'body']);
  });

  it('falls back to directory name and detects file names', () => {
    const t = parseSkillMd('/skills/renamed/SKILL.md', '---\ndescription: Only description\n---\nBody');
    expect(t.name).toBe('renamed');
    expect(isSkillMdFile('SKILL.md')).toBe(true);
    expect(isSkillMdFile('README.md')).toBe(false);
  });
});

describe('MCP config parser', () => {
  it('parses mcpServers, servers and flat shapes', () => {
    const a = parseMcpConfig('c.json', JSON.stringify({ mcpServers: { fs: { command: 'npx' } } }));
    expect(a.surfaces.map((s) => s.location)).toContain('mcpServers.fs');
    const b = parseMcpConfig('servers.json', JSON.stringify({ servers: { api: { url: 'https://x' } } }));
    expect(b.surfaces.map((s) => s.location)).toContain('mcpServers.api');
    const c = parseMcpConfig('settings.json', JSON.stringify({ dbtool: { command: 'db', args: ['--mcp'] } }));
    expect(c.surfaces.length).toBeGreaterThan(0);
  });

  it('extracts env lines and survives unparseable JSON', () => {
    const a = parseMcpConfig('c.json', JSON.stringify({ mcpServers: { gh: { command: 'npx', env: { GH_TOKEN: 'x' } } } }));
    expect(a.surfaces.map((s) => s.location)).toContain('mcpServers.gh.env');
    const b = parseMcpConfig('mcp.json', '{not json');
    expect(b.surfaces[0].location).toBe('file');
  });

  it('recognizes known config filenames only', () => {
    expect(isMcpConfigFile('.mcp.json')).toBe(true);
    expect(isMcpConfigFile('claude_desktop_config.json')).toBe(true);
    expect(isMcpConfigFile('package.json')).toBe(false);
  });
});
