import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import { evaluatePolicy } from '@/lib/governance/policy-engine';

const governanceRequestSchema = z.object({
  action: z.string().min(1).max(120),
  resource: z.string().max(120).optional(),
  dataClassification: z.enum(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'TOP_SECRET']).optional(),
  requestedModel: z.string().max(120).optional(),
  tools: z.array(z.string().max(120)).max(20).optional(),
  networkMode: z.enum(['local', 'air-gapped', 'external']).optional(),
});

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const parsed = governanceRequestSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid governance request', details: parsed.error.flatten() }, { status: 400 });
  }

  const decision = evaluatePolicy((session.user as { role?: string }).role, parsed.data);
  return NextResponse.json({
    requestId: `GOV-${crypto.randomUUID()}`,
    userId: session.user.id,
    ...decision,
  }, { status: decision.decision === 'DENY' ? 403 : 200 });
}