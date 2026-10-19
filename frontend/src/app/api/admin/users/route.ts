import { NextRequest, NextResponse } from 'next/server';
import { getAdminSessionOrReject } from '@/lib/authGuards';
import { listAllUsers, updateUserStatus, updateUserRole } from '@/lib/users';

export const runtime = 'nodejs';

export async function GET(request: NextRequest) {
  const auth = await getAdminSessionOrReject('Administrator privileges required to inspect user accounts');
  if (!auth.authorized) {
    return auth.response;
  }
  const session = auth.session;

  try {
    const { searchParams } = new URL(request.url);
    const search = searchParams.get('search')?.toLowerCase().trim() || '';
    const statusFilter = searchParams.get('status') || '';
    const roleFilter = searchParams.get('role') || '';

    const allUsers = await listAllUsers();

    let filtered = allUsers;
    if (search) {
      filtered = filtered.filter(
        u => u.name.toLowerCase().includes(search) || u.email.toLowerCase().includes(search)
      );
    }
    if (statusFilter) {
      filtered = filtered.filter(u => (u.status || 'active') === statusFilter);
    }
    if (roleFilter) {
      filtered = filtered.filter(u => u.role === roleFilter);
    }

    return NextResponse.json({
      users: filtered,
      total: filtered.length,
      operator: session.user.email,
    });
  } catch (error: unknown) {
    console.error('[Admin Users GET] Error:', error);
    return NextResponse.json({ error: 'Failed to retrieve users' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const auth = await getAdminSessionOrReject('Administrator privileges required');
  if (!auth.authorized) {
    return auth.response;
  }
  const session = auth.session;

  try {
    const body = await request.json();
    const { action, email, status, role } = body;

    if (!email) {
      return NextResponse.json({ error: 'Target user email is required' }, { status: 400 });
    }

    if (action === 'update_status') {
      if (!status || !['active', 'suspended', 'disabled'].includes(status)) {
        return NextResponse.json({ error: 'Invalid status value' }, { status: 400 });
      }
      const res = await updateUserStatus(email, status, session.user.email || undefined);
      if (!res.success) {
        return NextResponse.json({ error: res.message }, { status: 400 });
      }
      return NextResponse.json({ success: true, message: res.message, user: res.user });
    }

    if (action === 'update_role') {
      if (!role || !['admin', 'user'].includes(role)) {
        return NextResponse.json({ error: 'Invalid role value' }, { status: 400 });
      }
      const res = await updateUserRole(email, role, session.user.email || undefined);
      if (!res.success) {
        return NextResponse.json({ error: res.message }, { status: 400 });
      }
      return NextResponse.json({ success: true, message: res.message, user: res.user });
    }

    return NextResponse.json({ error: 'Unsupported action' }, { status: 400 });
  } catch (error: unknown) {
    console.error('[Admin Users POST] Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
