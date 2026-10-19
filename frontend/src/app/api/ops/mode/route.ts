import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import { updateAutonomyMode } from '@/lib/ops/autonomous-ops';

const modeSchema = z.object({
  mode: z.enum(['OBSERVE', 'RECOMMEND_AND_APPROVE', 'BOUNDED_AUTOMATION', 'READ_ONLY_ASSIST']),
});

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  const role = (session?.user as { role?: string } | undefined)?.role;
  if (!session?.user || role !== 'admin') {
    return NextResponse.json({ error: 'Administrator access required' }, { status: 403 });
  }

  try {
    const body = await request.json().catch(() => null);
    const parsed = modeSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: 'Invalid mode payload' }, { status: 400 });
    }

    const updated = await updateAutonomyMode(parsed.data.mode);
    return NextResponse.json({ status: 'MODE_UPDATED', new_mode: updated });
  } catch (error) {
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}
