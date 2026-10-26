import type { Rule } from './rule.js';
import { AST, LLM } from '../mapping.js';
import { evidenceFor, firstMatch } from '../util/text.js';

/**
 * SS-012 — Cloud instance-metadata and platform-internal endpoints in
 * agent-readable text. A skill that steers the agent at 169.254.169.254,
 * metadata.google.internal or the ECS/Azure/Alibaba equivalents is not doing
 * devops: instance metadata is where cloud IAM credentials live, and the only
 * reason agent text references it is to walk credentials out of the host.
 * Complements SS-002 (egress URLs) and SS-003 (credential paths) by covering
 * the network-internal start of the same kill chain.
 */
const PATTERNS: Array<{ re: RegExp; label: string; score: number }> = [
  // AWS/GCP/DigitalOcean/Hetzner link-local metadata (IMDS / equivalent)
  { re: /\b169\.254\.169\.254\b/g, label: 'link-local instance-metadata address (IMDS)', score: 9.5 },
  // AWS ECS task role credentials (the v2 endpoint)
  { re: /\b169\.254\.170\.2\b/g, label: 'AWS ECS task credentials endpoint', score: 9.5 },
  // GCP metadata hostnames (metadata.goog is the short public alias)
  { re: /\bmetadata\.google\.internal\b|\bmetadata\.goog\b/gi, label: 'GCP instance-metadata hostname', score: 9.5 },
  // AWS IMDS over IPv6
  { re: /\bfd00:ec2::254\b/gi, label: 'AWS IMDS IPv6 endpoint', score: 9 },
  // Alibaba Cloud metadata
  { re: /\b100\.100\.100\.200\b/g, label: 'Alibaba Cloud instance-metadata address', score: 9 },
  // Azure platform-internal wireserver (used for VM metadata/extensions)
  { re: /\b168\.63\.129\.16\b/g, label: 'Azure platform-internal wireserver address', score: 9 },
  // IMDS paths even without the address (proxied fetches)
  { re: /\/latest\/meta-data\//gi, label: 'AWS IMDS path (instance data / IAM credentials)', score: 8.5 },
  { re: /\bmetadata\/instance\b/gi, label: 'Azure IMDS path (instance metadata)', score: 8.5 },
  // IMDSv2 session-token header — evidence someone is scripting metadata access
  { re: /x-aws-ec2-metadata-token/gi, label: 'IMDSv2 token header (scripted metadata access)', score: 8.5 }
];

export const cloudMetadata: Rule = {
  id: 'SS-012',
  title: 'Cloud instance-metadata / platform-internal endpoint probing',
  description:
    'References to cloud instance-metadata endpoints (169.254.169.254, metadata.google.internal, ECS/Azure/Alibaba equivalents) or their access paths in agent-readable text or MCP command lines. Instance metadata is the canonical location of cloud IAM credentials; instructions that point an agent there are credential-theft setups that survive as plain text long after the host rotates keys.',
  remediation:
    'Remove all instance-metadata references from agent-reachable text. Agent tooling has no legitimate reason to read IMDS; if a workflow needs cloud credentials, inject them through a reviewed secret manager with scoped, short-lived tokens.',
  severity: 'critical',
  score: 9.5,
  standards: [AST.credentialHarvesting(), LLM.sensitiveInfo()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'critical'; score?: number }> = [];
    const seen = new Set<string>();
    for (const p of PATTERNS) {
      const m = firstMatch(p.re, surface.text);
      if (m && !seen.has(m[0])) {
        seen.add(m[0]);
        out.push({
          evidence: evidenceFor(surface.text, m[0]),
          note: `Matched pattern: ${p.label}`,
          severity: 'critical',
          score: p.score
        });
      }
    }
    return out;
  }
};
