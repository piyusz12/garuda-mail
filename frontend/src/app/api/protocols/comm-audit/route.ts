import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { auditDomainCommSecurity } from '@/lib/commSecurity';
import { z } from 'zod';

export const runtime = 'nodejs';

const domainQuerySchema = z.object({
  domain: z.string().min(2).max(255).refine(d => !/\s/.test(d), 'Invalid domain format'),
});

export async function GET(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const rawDomain = searchParams.get('domain') || 'gov.in';

  const parseResult = domainQuerySchema.safeParse({ domain: rawDomain });
  if (!parseResult.success) {
    return NextResponse.json({ error: parseResult.error.issues[0]?.message || 'Invalid domain' }, { status: 400 });
  }

  try {
    const audit = await auditDomainCommSecurity(parseResult.data.domain);
    return NextResponse.json(audit);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return NextResponse.json({ error: 'Failed to audit communication security', details: msg }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json().catch(() => ({}));
    const parseResult = domainQuerySchema.safeParse(body);
    if (!parseResult.success) {
      return NextResponse.json({ error: parseResult.error.issues[0]?.message || 'Invalid domain payload' }, { status: 400 });
    }

    const audit = await auditDomainCommSecurity(parseResult.data.domain);
    return NextResponse.json(audit);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return NextResponse.json({ error: 'Failed to audit communication security', details: msg }, { status: 500 });
  }
}
