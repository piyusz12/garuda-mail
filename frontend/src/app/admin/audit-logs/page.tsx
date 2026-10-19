import { requireAdminSession } from '@/lib/authGuards';
import AdminConsoleClient from '../AdminConsoleClient';

export default async function AdminAuditLogsPage() {
  const session = await requireAdminSession('/admin/audit-logs');

  return (
    <AdminConsoleClient
      currentUser={{
        name: session.user?.name,
        email: session.user?.email,
        role: session.user?.role,
      }}
      initialTab="audit"
    />
  );
}
