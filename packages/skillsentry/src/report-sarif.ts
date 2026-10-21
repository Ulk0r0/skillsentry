import type { ScanResult, Severity } from './types.js';
import { RULES_BY_ID } from './rules/index.js';
import { squash } from './util/text.js';

/**
 * SARIF 2.1.0 output — the static-analysis interchange format GitHub Code
 * Scanning, VS Code and many CI gateways ingest natively. Emitting SARIF
 * means SkillSentry findings can appear directly in GitHub's "Security" tab
 * via `github/codeql-action/upload-sarif`, with zero glue code.
 *
 * Note on locations: SkillSentry surfaces are logical (frontmatter.description,
 * mcpServers.<name>.env), not byte regions, so results carry the artifact URI
 * plus the logical location in `properties` instead of a synthetic region.
 */

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note'
};

export interface SarifOptions {
  /** Tool version written into runs[].tool.driver.version. */
  toolVersion?: string;
  /** When set, artifact URIs under this directory become repo-relative. */
  root?: string;
  /** Driver informationUri (defaults to the project homepage). */
  informationUri?: string;
}

const DEFAULT_INFORMATION_URI = 'https://github.com/Ulk0r0/skillsentry';

function relativize(p: string, root?: string): string {
  if (!root) return p;
  const base = root.endsWith('/') ? root.slice(0, -1) : root;
  return p === base || p.startsWith(`${base}/`) ? p.slice(base.length + 1) : p;
}

/** Deterministic: rule list and results are emitted in stable, sorted order. */
export function renderSarif(result: ScanResult, opts: SarifOptions = {}): string {
  const informationUri = opts.informationUri ?? DEFAULT_INFORMATION_URI;

  const ruleIds = [...new Set(result.reports.flatMap((r) => r.findings.map((f) => f.ruleId)))].sort();
  const rules = ruleIds.map((id) => {
    const rule = RULES_BY_ID.get(id);
    return {
      id,
      name: rule?.title ?? id,
      shortDescription: { text: rule?.description ?? id },
      help: rule ? { text: rule.remediation } : undefined,
      helpUri: rule?.standards.find((s) => s.url)?.url ?? informationUri,
      defaultConfiguration: { level: SARIF_LEVEL[rule?.severity ?? 'medium'] }
    };
  });

  const results = result.reports.flatMap((r) =>
    r.findings.map((f) => ({
      ruleId: f.ruleId,
      level: SARIF_LEVEL[f.severity],
      message: { text: `${f.title} [${f.ruleId}] — ${squash(f.evidence).slice(0, 200)}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: relativize(r.path, opts.root) }
          }
        }
      ],
      properties: {
        severity: f.severity,
        score: f.score,
        logicalLocation: f.location,
        fileKind: r.kind,
        fileVerdict: r.verdict,
        fileRiskScore: r.riskScore,
        standards: f.standards.map((s) => `${s.framework}:${s.id}`)
      }
    }))
  );

  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'SkillSentry',
              version: opts.toolVersion,
              informationUri,
              rules: rules.length ? rules : undefined
            }
          },
          columnKind: 'utf16CodeUnits',
          results
        }
      ]
    },
    null,
    2
  );
}
