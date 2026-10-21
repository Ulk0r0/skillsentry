import { NextResponse } from 'next/server';
import { scanText } from 'skillsentry';

export const runtime = 'nodejs';

export async function POST(req: Request) {
  let body: { filename?: string; content?: string; ai?: boolean };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  const content = typeof body.content === 'string' ? body.content : '';
  if (!content.trim()) {
    return NextResponse.json({ error: 'content is empty' }, { status: 400 });
  }
  const filename = typeof body.filename === 'string' && body.filename.trim() ? body.filename.trim() : 'SKILL.md';

  try {
    const report = await scanText(filename, content, { ai: body.ai !== false, aiTimeoutMs: 30_000 });
    return NextResponse.json({ report });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : 'scan failed' },
      { status: 500 }
    );
  }
}
