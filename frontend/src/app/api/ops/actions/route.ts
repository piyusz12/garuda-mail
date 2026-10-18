import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import {
  fetchActionPlans,
  approveActionPlan,
  executeActionPlan,
  rollbackActionPlan,
} from '@/lib/ops/autonomous-ops';

const actionCommandSchema = z.object({
  action_id: z.string().min(1).max(120),
  command: z.enum(['approve', 'execute', 'rollback']),
});

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const data = await fetchActionPlans();
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  const role = (session?.user as { role?: string } | undefined)?.role;
  if (!session?.user || role !== 'admin') {
    return NextResponse.json({ error: 'Administrator access required' }, { status: 403 });
  }

  try {
    const body = await request.json().catch(() => null);
    const parsed = actionCommandSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: 'Invalid action payload', details: parsed.error.format() }, { status: 400 });
    }

    const { action_id, command } = parsed.data;

    if (command === 'approve') {
      const plan = await approveActionPlan(action_id);
      return NextResponse.json({ status: 'APPROVED', plan });
    } else if (command === 'execute') {
      const res = await executeActionPlan(action_id);
      return NextResponse.json(res);
    } else if (command === 'rollback') {
      const res = await rollbackActionPlan(action_id);
      return NextResponse.json(res);
    }
  } catch (error) {
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}
