import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import { evaluatePolicy } from '@/lib/governance/policy-engine';
import { scheduleWorkload } from '@/lib/fabric/scheduler';

const scheduleSchema = z.object({
  action: z.string().min(1).max(120),
  capability: z.string().min(1).max(80),
  model: z.string().max(120).optional(),
  minVramGb: z.number().min(0).max(512).optional(),
  dataClassification: z.enum(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'TOP_SECRET']).optional(),
  allowedZones: z.array(z.string().max(80)).max(20).optional(),
  priority: z.enum(['critical', 'high', 'normal', 'low', 'background']).optional(),
});

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const parsed = scheduleSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: 'Invalid scheduling request' }, { status: 400 });

  const policy = evaluatePolicy((session.user as { role?: string }).role, {
    action: parsed.data.action,
    resource: 'fabric-workload',
    dataClassification: parsed.data.dataClassification,
    requestedModel: parsed.data.model,
    networkMode: 'local',
  });
  if (policy.decision !== 'ALLOW') {
    return NextResponse.json({ policy, scheduled: false }, { status: policy.decision === 'DENY' ? 403 : 202 });
  }

  const schedule = scheduleWorkload(parsed.data);
  if (!schedule.selectedNode) return NextResponse.json({ policy, schedule, scheduled: false }, { status: 503 });
  return NextResponse.json({ policy, schedule, scheduled: true });
}