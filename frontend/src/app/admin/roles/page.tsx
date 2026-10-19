import { requireAdminSession } from '@/lib/authGuards';
import AdminConsoleClient from '../AdminConsoleClient';

export default async function AdminRolesPage() {
  const session = await requireAdminSession('/admin/roles');

  return (
    <AdminConsoleClient
      currentUser={{
        name: session.user?.name,
        email: session.user?.email,
        role: session.user?.role,
      }}
      initialTab="roles"
    />
  );
}
