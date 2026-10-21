import { NextResponse } from 'next/server';
import { promises as fs } from 'node:fs';
import path from 'node:path';

export const runtime = 'nodejs';

interface Sample {
  id: string;
  label: string;
  group: 'clean' | 'poisoned';
  filename: string;
  content: string;
}

/**
 * Serves the repo's samples/ gallery so the dashboard can load real fixtures.
 * Read directly from disk (dev/demo usage); returns an empty list when the
 * folder is not present (e.g. standalone builds).
 */
export async function GET() {
  const root = path.resolve(process.cwd(), '..', '..', 'samples');
  const out: Sample[] = [];

  async function walk(dir: string, rel: string, group: 'clean' | 'poisoned'): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      const relPath = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        await walk(full, relPath, group);
      } else if (e.isFile() && (e.name === 'SKILL.md' || e.name === 'claude_desktop_config.json')) {
        try {
          const content = await fs.readFile(full, 'utf8');
          out.push({
            id: relPath,
            label: relPath.replace(/\/SKILL\.md$/, '').replace(/\/claude_desktop_config\.json$/, ' (mcp)'),
            group,
            filename: e.name,
            content
          });
        } catch {
          /* ignore unreadable files */
        }
      }
    }
  }

  await walk(path.join(root, 'skills', 'clean'), 'clean', 'clean');
  await walk(path.join(root, 'skills', 'poisoned'), 'poisoned', 'poisoned');
  await walk(path.join(root, 'mcp', 'clean'), 'mcp-clean', 'clean');
  await walk(path.join(root, 'mcp', 'evil'), 'mcp-evil', 'poisoned');

  return NextResponse.json({ samples: out });
}
