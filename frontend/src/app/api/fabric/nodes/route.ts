import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import { applyHeartbeat, listNodes, quarantineNode } from '@/lib/fabric/node-registry';
import { getClusterMetrics } from '@/lib/fabric/cluster-service';

const heartbeatSchema = z.object({
  nodeId: z.string().min(1).max(80),
  status: z.enum(['healthy', 'degraded', 'unavailable', 'recovering', 'quarantined']).optional(),
  cpuUsagePct: z.number().min(0).max(100).optional(),
  ramUsedGb: z.number().min(0).optional(),
  vramUsedGb: z.number().min(0).optional(),
  activeJobs: z.number().int().min(0).optional(),
  temperatureC: z.number().optional(),
  capabilities: z.array(z.string().max(80)).max(30).optional(),
  models: z.array(z.string().max(120)).max(30).optional(),
});

const actionSchema = z.object({
  action: z.enum(['quarantine', 'heartbeat']),
  nodeId: z.string().min(1),
  reason: z.string().optional(),
});

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const nodes = listNodes();
  return NextResponse.json({
    nodes,
    count: nodes.length,
    metrics: getClusterMetrics(),
  });
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

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  const role = (session?.user as { role?: string } | undefined)?.role;
  if (!session?.user || role !== 'admin') {
    return NextResponse.json({ error: 'Administrator access required' }, { status: 403 });
  }

  const parsed = actionSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: 'Invalid action payload' }, { status: 400 });

  if (parsed.data.action === 'quarantine') {
    const node = quarantineNode(parsed.data.nodeId, parsed.data.reason || 'Admin quarantine action');
    if (!node) return NextResponse.json({ error: 'Node not found' }, { status: 404 });
    return NextResponse.json({ success: true, node });
  }

  return NextResponse.json({ error: 'Action not supported' }, { status: 400 });
}