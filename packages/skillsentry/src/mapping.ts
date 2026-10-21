import type { StandardRef } from './types.js';
import { STANDARD_URLS } from './types.js';

/**
 * Convenience builders for the three standards SkillSentry maps findings to.
 *
 * - OWASP LLM Top 10 (2026) — official IDs LLM01..LLM10 (published 2026-08-04).
 * - AST10 — OWASP Agentic Skills Top 10, v1.0-2026; covers SKILL.md/skill.json
 *   supply-chain threats. Descriptors below are informal slugs pending the
 *   project's own per-item identifiers; `url` points at the official repo.
 * - OWASP MCP Top 10 — Model Context Protocol Top 10; same approach.
 */

export const LLM = {
  promptInjection: (name = 'LLM01: Prompt Injection'): StandardRef => ({
    framework: 'OWASP LLM Top 10 (2026)', id: 'LLM01', name, url: STANDARD_URLS.llmTop10
  }),
  sensitiveInfo: (): StandardRef => ({
    framework: 'OWASP LLM Top 10 (2026)', id: 'LLM02', name: 'LLM02: Sensitive Information Disclosure', url: STANDARD_URLS.llmTop10
  }),
  excessiveAgency: (): StandardRef => ({
    framework: 'OWASP LLM Top 10 (2026)', id: 'LLM03', name: 'LLM03: Excessive Agency', url: STANDARD_URLS.llmTop10
  }),
  supplyChain: (): StandardRef => ({
    framework: 'OWASP LLM Top 10 (2026)', id: 'LLM04', name: 'LLM04: Supply Chain', url: STANDARD_URLS.llmTop10
  }),
  dataPoisoning: (): StandardRef => ({
    framework: 'OWASP LLM Top 10 (2026)', id: 'LLM05', name: 'LLM05: Data and Model Poisoning', url: STANDARD_URLS.llmTop10
  }),
  improperOutput: (): StandardRef => ({
    framework: 'OWASP LLM Top 10 (2026)', id: 'LLM10', name: 'LLM10: Improper Output Handling', url: STANDARD_URLS.llmTop10
  })
};

export const AST = {
  poisoning: (): StandardRef => ({
    framework: 'AST10', id: 'ast10:skill-poisoning', name: 'AST10: Poisoned skill instructions', url: STANDARD_URLS.ast10
  }),
  covertDataFlow: (): StandardRef => ({
    framework: 'AST10', id: 'ast10:covert-data-flow', name: 'AST10: Covert data exfiltration via skills', url: STANDARD_URLS.ast10
  }),
  credentialHarvesting: (): StandardRef => ({
    framework: 'AST10', id: 'ast10:credential-harvesting', name: 'AST10: Credential & secret harvesting', url: STANDARD_URLS.ast10
  }),
  deceptiveMetadata: (): StandardRef => ({
    framework: 'AST10', id: 'ast10:deceptive-metadata', name: 'AST10: Deceptive skill metadata', url: STANDARD_URLS.ast10
  }),
  toolShadowing: (): StandardRef => ({
    framework: 'AST10', id: 'ast10:tool-shadowing', name: 'AST10: Cross-tool shadowing / routing hijack', url: STANDARD_URLS.ast10
  })
};

export const MCP = {
  toolPoisoning: (): StandardRef => ({
    framework: 'OWASP MCP Top 10', id: 'mcp:tool-poisoning', name: 'MCP Top 10: Tool poisoning / description manipulation', url: STANDARD_URLS.mcpTop10
  }),
  rugPull: (): StandardRef => ({
    framework: 'OWASP MCP Top 10', id: 'mcp:tool-rug-pull', name: 'MCP Top 10: Tool rug-pull / silent behavior change', url: STANDARD_URLS.mcpTop10
  }),
  insecureConfig: (): StandardRef => ({
    framework: 'OWASP MCP Top 10', id: 'mcp:insecure-server-config', name: 'MCP Top 10: Insecure server configuration', url: STANDARD_URLS.mcpTop10
  })
};

/** Every framework we reference, for docs and the dashboard legend. */
export const FRAMEWORKS = [
  { name: 'OWASP LLM Top 10 (2026)', url: STANDARD_URLS.llmTop10 },
  { name: 'AST10 — Agentic Skills Top 10 (v1.0-2026)', url: STANDARD_URLS.ast10 },
  { name: 'OWASP MCP Top 10', url: STANDARD_URLS.mcpTop10 }
] as const;
