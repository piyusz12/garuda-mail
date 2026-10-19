import { requireAdminSession } from '@/lib/authGuards';
import AdminConsoleClient from '../AdminConsoleClient';

export default async function AdminSecurityPage() {
  const session = await requireAdminSession('/admin/security');

  return (
    <AdminConsoleClient
      currentUser={{
        name: session.user?.name,
        email: session.user?.email,
        role: session.user?.role,
      }}
      initialTab="security"
    />
  );
}
