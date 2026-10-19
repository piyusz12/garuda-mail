import { requireAdminSession } from '@/lib/authGuards';
import AdminConsoleClient from '../AdminConsoleClient';

export default async function AdminSettingsPage() {
  const session = await requireAdminSession('/admin/settings');

  return (
    <AdminConsoleClient
      currentUser={{
        name: session.user?.name,
        email: session.user?.email,
        role: session.user?.role,
      }}
      initialTab="settings"
    />
  );
}
