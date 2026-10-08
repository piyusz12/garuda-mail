import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import { applyHeartbeat, listNodes } from '@/lib/fabric/node-registry';

const heartbeatSchema = z.object({
  nodeId: z.string().min(1).max(80),
  status: z.enum(['healthy', 'degraded', 'unavailable', 'quarantined']).optional(),
  vramUsedGb: z.number().min(0).optional(),
  activeJobs: z.number().int().min(0).optional(),
  capabilities: z.array(z.string().max(80)).max(30).optional(),
  models: z.array(z.string().max(120)).max(30).optional(),
});

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  return NextResponse.json({ nodes: listNodes(), count: listNodes().length });
}

export async function PATCH(request: Request) {
  const session = await getServerSession(authOptions);
  const role = (session?.user as { role?: string } | undefined)?.role;
  if (!session?.user || role !== 'admin') {
    return NextResponse.json({ error: 'Administrator access required' }, { status: 403 });
  }

  const parsed = heartbeatSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: 'Invalid node heartbeat' }, { status: 400 });
  const node = applyHeartbeat(parsed.data);
  if (!node) return NextResponse.json({ error: 'Unknown node' }, { status: 404 });
  return NextResponse.json({ node });
}