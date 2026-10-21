import type { ScanSurface, ScanTarget } from '../types.js';
import { parseFrontmatter } from '../util/text.js';
import path from 'node:path';

/**
 * Parse a SKILL.md file (Agent Skills spec: frontmatter `name` + `description`,
 * markdown body) into scan surfaces. The description is the highest-value
 * surface: agents read it to decide when to invoke the skill, which makes it
 * the classic injection point for poisoned instructions.
 */
export function parseSkillMd(filePath: string, raw: string): ScanTarget {
  const fm = parseFrontmatter(raw);
  const name = typeof fm.data.name === 'string' && fm.data.name ? fm.data.name : path.basename(path.dirname(filePath));
  const surfaces: ScanSurface[] = [];

  if (typeof fm.data.description === 'string' && fm.data.description.trim()) {
    surfaces.push({ location: 'frontmatter.description', text: fm.data.description });
  }
  // Any other frontmatter field is free-form text an attacker can use too.
  const otherFm = Object.entries(fm.data)
    .filter(([k]) => k !== 'name' && k !== 'description')
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join('; ') : v}`)
    .join('\n');
  if (otherFm.trim()) {
    surfaces.push({ location: 'frontmatter.other', text: otherFm });
  }
  if (fm.body.trim()) {
    surfaces.push({ location: 'body', text: fm.body });
  }
  return { path: filePath, kind: 'skill-md', name, surfaces };
}

/** True when the filename should be treated as an Agent Skill document. */
export function isSkillMdFile(fileName: string): boolean {
  return fileName === 'SKILL.md' || fileName === 'skill.md';
}
