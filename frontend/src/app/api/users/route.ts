import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { listAllUsers } from '@/lib/users';

export async function GET(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const role = (session.user as { role?: string }).role;
  if (role !== 'admin' && role !== 'officer') {
    return NextResponse.json(
      { error: 'Forbidden: Insufficient privileges to view user directory' },
      { status: 403 }
    );
  }

  try {
    const users = await listAllUsers();
    return NextResponse.json({ users });
  } catch (error: unknown) {
    console.error('[Users GET] Error:', error);
    return NextResponse.json({ error: 'Failed to fetch users' }, { status: 500 });
  }
}
