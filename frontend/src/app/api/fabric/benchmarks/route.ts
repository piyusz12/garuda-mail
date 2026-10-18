import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authOptions } from '@/lib/auth';
import { runBenchmark } from '@/lib/fabric/cluster-service';

const benchSchema = z.object({
  count: z.number().int().min(10).max(200).optional(),
});

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const result = runBenchmark(50);
  return NextResponse.json(result);
}

export async function POST(request: Request) {
  const session = await getServerSession(authOptions);
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const parsed = benchSchema.safeParse(await request.json().catch(() => ({})));
  const count = parsed.success && parsed.data.count ? parsed.data.count : 50;

  const result = runBenchmark(count);
  return NextResponse.json(result);
}
