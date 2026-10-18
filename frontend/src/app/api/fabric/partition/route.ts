import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import { isAirGapped, setAirGapped } from '@/lib/fabric/cluster-service';

const toggleSchema = z.object({
  enabled: z.boolean(),
});

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  return NextResponse.json({ airGapped: isAirGapped() });
}

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  const role = (session?.user as { role?: string } | undefined)?.role;
  if (!session?.user || role !== 'admin') {
    return NextResponse.json({ error: 'Administrator access required to toggle partition mode' }, { status: 403 });
  }

  const parsed = toggleSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: 'Invalid payload' }, { status: 400 });

  const status = setAirGapped(parsed.data.enabled);
  return NextResponse.json({
    airGapped: status,
    message: status
      ? 'Air-Gapped Partition Mode ENABLED: External AI cloud egress blocked.'
      : 'Partition Mode DISABLED: Hybrid mesh connectivity active.',
  });
}
