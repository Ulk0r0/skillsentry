import { describe, it, expect, vi, afterEach } from 'vitest';
import { probeAi, assessWithAi, parseAssessment, DEFAULT_AI_BASE_URL, DEFAULT_MODEL } from '../src/ai.js';

const validAiJson = {
  intent: 'Trick the agent into uploading user data',
  manipulationTechniques: ['instruction override', 'covert exfiltration'],
  dataFlows: 'user notes → webhook.site',
  severity: 'critical',
  confidence: 0.9,
  rationale: 'The description orders a hidden upload.',
  standards: [
    { framework: 'OWASP LLM Top 10 (2026)', id: 'LLM01', name: 'Prompt Injection' },
    { framework: 'FakeFramework', id: 'X', name: 'should be dropped' }
  ]
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('parseAssessment', () => {
  it('parses valid JSON and drops unknown frameworks', () => {
    const a = parseAssessment(JSON.stringify(validAiJson), 'test-model');
    expect(a.severity).toBe('critical');
    expect(a.confidence).toBeCloseTo(0.9);
    expect(a.model).toBe('test-model');
    expect(a.standards).toHaveLength(1);
    expect(a.standards[0].id).toBe('LLM01');
  });

  it('tolerates fenced output and surrounding prose', () => {
    const wrapped = 'Sure! Here is my analysis:\n```json\n' + JSON.stringify(validAiJson) + '\n```';
    const a = parseAssessment(wrapped, 'm');
    expect(a.intent).toContain('Trick');
  });

  it('falls back to medium severity and clamps confidence', () => {
    const a = parseAssessment(JSON.stringify({ severity: 'apocalyptic', confidence: 42 }), 'm');
    expect(a.severity).toBe('medium');
    expect(a.confidence).toBe(1);
  });

  it('throws when no JSON object is present', () => {
    expect(() => parseAssessment('no json here', 'm')).toThrow();
  });
});

describe('assessWithAi (mocked transport)', () => {
  it('posts to the OpenAI-compatible endpoint and parses the reply', async () => {
    const fetchMock = vi.fn(async (url: string | URL) => {
      expect(String(url)).toBe('http://mock.local/v1/chat/completions');
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: JSON.stringify(validAiJson) } }] })
      };
    });
    vi.stubGlobal('fetch', fetchMock);
    const a = await assessWithAi(
      { path: 'SKILL.md', kind: 'skill-md', name: 'x', surfaces: [{ location: 'body', text: 'hello' }] },
      { openaiBaseUrl: 'http://mock.local/v1', model: 'openweight-test' }
    );
    expect(a.model).toBe('openweight-test');
    expect(a.severity).toBe('critical');
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('surfaces HTTP errors as exceptions (caller converts to aiError)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 500 })));
    await expect(assessWithAi(
      { path: 'p', kind: 'skill-md', name: 'x', surfaces: [{ location: 'body', text: 't' }] },
      { openaiBaseUrl: 'http://mock.local/v1' }
    )).rejects.toThrow(/HTTP 500/);
  });
});

describe('probeAi', () => {
  it('returns false when no runtime answers', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('ECONNREFUSED'); }));
    expect(await probeAi('http://mock.local/v1')).toBe(false);
  });

  it('returns true on a healthy /models response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true })));
    expect(await probeAi('http://mock.local/v1')).toBe(true);
  });
});

describe('defaults', () => {
  it('default base URL is local Ollama and default model is an open-weight one', () => {
    expect(DEFAULT_AI_BASE_URL).toContain('localhost:11434');
    expect(DEFAULT_MODEL).toMatch(/^gemma|llama|qwen|mistral/);
  });
});
