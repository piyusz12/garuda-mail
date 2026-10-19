import { NextRequest, NextResponse } from 'next/server';
import { getAdminSessionOrReject } from '@/lib/authGuards';
import { listAllUsers } from '@/lib/users';
import { getAuditLogs } from '@/lib/audit';
import { API_CONFIG, getBackendUrl } from '@/lib/api/config';

export const runtime = 'nodejs';

export async function GET(request: NextRequest) {
  const auth = await getAdminSessionOrReject('Administrator privileges required');
  if (!auth.authorized) {
    return auth.response;
  }

  try {
    const users = await listAllUsers();
    const auditLogs = await getAuditLogs(20);

    const totalUsers = users.length;
    const activeUsers = users.filter(u => (u.status || 'active') === 'active').length;
    const suspendedUsers = users.filter(u => u.status === 'suspended').length;
    const adminCount = users.filter(u => u.role === 'admin').length;
    const standardUserCount = users.filter(u => u.role !== 'admin').length;

    // Fast check on Python backend using centralized API config
    let backendStatus: 'connected' | 'offline' = 'offline';
    try {
      const res = await fetch(getBackendUrl(API_CONFIG.ENDPOINTS.HEALTH), {
        signal: AbortSignal.timeout(1200),
      });
      if (res.ok) backendStatus = 'connected';
    } catch {}

    return NextResponse.json({
      stats: {
        totalUsers,
        activeUsers,
        suspendedUsers,
        adminCount,
        standardUserCount,
        recentRegistrations: users.slice(-5).reverse(),
        totalAuditEvents: auditLogs.length,
        systemHealth: {
          authService: 'healthy',
          databasePersistence: 'active',
          fastApiBackend: backendStatus,
          cryptographicEngine: 'operational',
          pqcReadiness: 'hybrid-ready',
        },
      },
      recentAuditLogs: auditLogs.slice(0, 10),
      timestamp: new Date().toISOString(),
    });
  } catch (error: unknown) {
    console.error('[Admin Stats GET] Error:', error);
    return NextResponse.json({ error: 'Failed to compile admin statistics' }, { status: 500 });
  }
}
