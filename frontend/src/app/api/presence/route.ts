import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { getDirectoryWithPresence, recordUserHeartbeat } from '@/lib/presence';

export async function GET(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.email) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const data = await getDirectoryWithPresence(session.user.email);
    return NextResponse.json(data);
  } catch (error: unknown) {
    console.error('[Presence GET] Error:', error);
    return NextResponse.json({ error: 'Failed to retrieve presence' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.email) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    recordUserHeartbeat(session.user.email);
    return NextResponse.json({ ok: true, timestamp: Date.now() });
  } catch (error: unknown) {
    console.error('[Presence POST] Error:', error);
    return NextResponse.json({ error: 'Failed to record heartbeat' }, { status: 500 });
  }
}
