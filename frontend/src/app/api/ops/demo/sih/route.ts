import { getServerSession } from 'next-auth';
import { NextResponse } from 'next/server';
import { authOptions } from '@/lib/auth';
import { runSIHDemo } from '@/lib/ops/autonomous-ops';

export async function POST() {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const role = (session.user as { role?: string })?.role;
  if (role !== 'admin' && role !== 'officer') {
    return NextResponse.json({ error: 'Forbidden: Officer or Admin privileges required' }, { status: 403 });
  }

  try {
    const data = await runSIHDemo();
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}
