import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { getDirectoryWithPresence } from '@/lib/presence';

export async function GET(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user?.email) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const { users, onlineCount } = await getDirectoryWithPresence(session.user.email);
    return NextResponse.json({ users, onlineCount });
  } catch (error: unknown) {
    console.error('[Users GET] Error:', error);
    return NextResponse.json({ error: 'Failed to fetch users' }, { status: 500 });
  }
}
