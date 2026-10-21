'use client';

import { useCallback, useEffect, useState } from 'react';
import type { ScanReport, Severity } from 'skillsentry';

interface Sample {
  id: string;
  label: string;
  group: 'clean' | 'poisoned';
  filename: string;
  content: string;
}

const SHIELD = (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden>
    <path d="M12 2L4 5.5V11c0 5 3.4 9.3 8 10.5 4.6-1.2 8-5.5 8-10.5V5.5L12 2z" stroke="#34d399" strokeWidth="1.6" fill="rgba(52,211,153,0.08)" />
    <path d="M9 12l2.2 2.2L15.5 9.7" stroke="#34d399" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export default function Home() {
  const [samples, setSamples] = useState<Sample[]>([]);
  const [activeSample, setActiveSample] = useState<string | null>(null);
  const [filename, setFilename] = useState('SKILL.md');
  const [content, setContent] = useState('');
  const [aiEnabled, setAiEnabled] = useState(true);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/samples')
      .then((r) => r.json())
      .then((d: { samples: Sample[] }) => setSamples(d.samples ?? []))
      .catch(() => setSamples([]));
  }, []);

  const loadSample = useCallback((s: Sample) => {
    setActiveSample(s.id);
    setFilename(s.filename);
    setContent(s.content);
    setReport(null);
    setError(null);
  }, []);

  const scan = useCallback(async () => {
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ filename, content, ai: aiEnabled })
      });
      const data = (await res.json()) as { report?: ScanReport; error?: string };
      if (!res.ok || !data.report) throw new Error(data.error ?? `HTTP ${res.status}`);
      setReport(data.report);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'scan failed');
    } finally {
      setLoading(false);
    }
  }, [filename, content, aiEnabled]);

  return (
    <main className="wrap">
      <header className="top">
        <div className="logo">{SHIELD}</div>
        <h1>
          Skill<span>Sentry</span>
        </h1>
      </header>
      <p className="tagline">
        Local-first security scanner for AI agent skills (SKILL.md) and MCP server configs — static rules + a local
        open-weight model. Nothing you paste here leaves your machine.
      </p>

      <div className="grid">
        <section className="panel">
          <h2>Sample gallery</h2>
          <div className="chips">
            {samples.map((s) => (
              <button
                key={s.id}
                className={`chip ${activeSample === s.id ? 'active' : ''}`}
                onClick={() => loadSample(s)}
                title={s.group === 'clean' ? 'Clean fixture — should scan clean' : 'Deliberately poisoned fixture'}
              >
                {s.group === 'clean' ? '✓' : '✗'} {s.label}
              </button>
            ))}
            {samples.length === 0 && <span className="small">samples not available in this deployment — paste your own below</span>}
          </div>

          <h2>Target</h2>
          <textarea
            value={content}
            onChange={(e) => {
              setContent(e.target.value);
              setActiveSample(null);
            }}
            placeholder={'---\nname: my-skill\ndescription: What this skill does for the user.\n---\n# Instructions\n…'}
            spellCheck={false}
          />
          <div className="row">
            <label className="fileInput">
              filename
              <input value={filename} onChange={(e) => setFilename(e.target.value)} />
            </label>
            <label className="toggle">
              <input type="checkbox" checked={aiEnabled} onChange={(e) => setAiEnabled(e.target.checked)} />
              AI layer (local open-weight model)
            </label>
            <button className="scan" onClick={scan} disabled={loading || !content.trim()}>
              {loading ? 'Scanning…' : 'Scan'}
            </button>
          </div>
          <p className="small">
            With no Ollama running, the scan degrades gracefully to static rules — the toggle just shows you the
            difference.
          </p>
        </section>

        <section className="panel">
          <h2>Report</h2>
          {error && <p className="aiErr">Error: {error}</p>}
          {!report && !error && (
            <div className="empty">
              Load a sample or paste a SKILL.md / MCP config, then press <b>Scan</b>.
              <br />
              The engine is the same one the CLI runs — including the OWASP mappings.
            </div>
          )}
          {report && (
            <>
              <div className="verdictLine">
                <span className={`badge ${report.verdict}`}>{report.verdict.toUpperCase()}</span>
                <div className="riskBar">
                  <div className="riskFill" style={{ width: `${report.riskScore}%` }} />
                </div>
                <span className="riskNum">risk {report.riskScore}/100 · {report.findings.length} finding(s) · {report.durationMs} ms</span>
              </div>

              {report.findings.length === 0 && <p className="small">No static findings. Clean bill of health from the rule engine.</p>}

              {report.findings.map((f, i) => (
                <div className="finding" key={`${f.ruleId}-${i}`}>
                  <div className="fhead">
                    <span className={`sev ${f.severity}`}>{f.severity.toUpperCase()}</span>
                    <span className="ruleId">{f.ruleId}</span>
                    <span className="fscore">score {f.score}</span>
                  </div>
                  <div className="ftitle">{f.title}</div>
                  <div className="floc">location: {f.location}</div>
                  <div className="fev">{f.evidence}</div>
                  {f.standards.length > 0 && (
                    <div className="fstd">
                      {f.standards.map((s) => (
                        <span className="std" key={`${s.framework}-${s.id}`}>
                          {s.id} · {s.framework}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}

              {report.ai && (
                <div className="aiBlock">
                  <h3>◆ AI review — local open-weight model</h3>
                  <div className="meta">
                    {report.ai.model} · severity {report.ai.severity} · confidence {(report.ai.confidence * 100).toFixed(0)}%
                  </div>
                  <p>
                    <span className="lbl">intent: </span>
                    {report.ai.intent}
                  </p>
                  <p>
                    <span className="lbl">data flows: </span>
                    {report.ai.dataFlows}
                  </p>
                  {report.ai.manipulationTechniques.length > 0 && (
                    <p>
                      <span className="lbl">techniques: </span>
                      {report.ai.manipulationTechniques.join(', ')}
                    </p>
                  )}
                  <p>
                    <span className="lbl">why: </span>
                    {report.ai.rationale}
                  </p>
                </div>
              )}
              {report.aiError && (
                <div className="aiBlock">
                  <h3>◆ AI review unavailable</h3>
                  <p className="aiErr">{report.aiError} — static findings above are complete and stand on their own.</p>
                </div>
              )}
            </>
          )}
        </section>
      </div>

      <footer>
        SkillSentry · MIT · <a href="https://github.com/Ulk0r0/skillsentry">github.com/Ulk0r0/skillsentry</a> — the CLI
        does everything this page does, and more: <code>npx skillsentry . --json --fail-on high</code>
      </footer>
    </main>
  );
}
