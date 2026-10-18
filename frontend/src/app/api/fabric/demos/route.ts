import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import { runSIHDemo } from '@/lib/fabric/cluster-service';

const demoSchema = z.object({
  demoId: z.number().int().min(1).max(6),
});

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  return NextResponse.json({
    demos: [
      { id: 1, title: 'Demo 1 — Distributed Inference', section: '34.40' },
      { id: 2, title: 'Demo 2 — Resource-Aware Scheduling', section: '34.41' },
      { id: 3, title: 'Demo 3 — Sovereign Data Placement', section: '34.42' },
      { id: 4, title: 'Demo 4 — Node Failure & Automatic Failover', section: '34.43' },
      { id: 5, title: 'Demo 5 — Air-Gapped Mode', section: '34.44' },
      { id: 6, title: 'Demo 6 — Policy + Scheduler End-to-End Chain', section: '34.45' },
    ],
  });
}

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const parsed = demoSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: 'Invalid demo request. demoId must be 1-6' }, { status: 400 });

  const result = runSIHDemo(parsed.data.demoId);
  return NextResponse.json(result);
}
