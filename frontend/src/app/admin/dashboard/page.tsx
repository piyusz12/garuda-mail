import { requireAdminSession } from '@/lib/authGuards';
import AdminConsoleClient from '../AdminConsoleClient';

export default async function AdminDashboardPage() {
  const session = await requireAdminSession('/admin/dashboard');

  return (
    <AdminConsoleClient
      currentUser={{
        name: session.user?.name,
        email: session.user?.email,
        role: session.user?.role,
      }}
      initialTab="overview"
    />
  );
}
