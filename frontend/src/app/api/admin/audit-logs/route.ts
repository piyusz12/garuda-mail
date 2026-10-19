import { NextRequest, NextResponse } from 'next/server';
import { getAdminSessionOrReject } from '@/lib/authGuards';
import { getAuditLogs } from '@/lib/audit';

export const runtime = 'nodejs';

export async function GET(request: NextRequest) {
  const auth = await getAdminSessionOrReject('Administrator privileges required to access audit records');
  if (!auth.authorized) {
    return auth.response;
  }

  try {
    const { searchParams } = new URL(request.url);
    const limitParam = parseInt(searchParams.get('limit') || '100', 10);
    const limit = isNaN(limitParam) ? 100 : Math.min(Math.max(limitParam, 1), 500);

    const logs = await getAuditLogs(limit);
    return NextResponse.json({ logs, total: logs.length });
  } catch (error: unknown) {
    console.error('[AuditLogs GET] Error:', error);
    return NextResponse.json({ error: 'Failed to retrieve audit logs' }, { status: 500 });
  }
}
