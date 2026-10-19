import { getServerSession } from 'next-auth';
import { redirect } from 'next/navigation';
import { authOptions } from '@/lib/auth';
import { hasRoleAccess } from '@/lib/roles';
import AdminConsoleClient from './AdminConsoleClient';

export default async function AdminPage() {
  const session = await getServerSession(authOptions);

  if (!session || !hasRoleAccess(session.user?.role, ['admin'])) {
    redirect('/login?callbackUrl=/admin');
  }

  return (
    <AdminConsoleClient
      currentUser={{
        name: session.user?.name,
        email: session.user?.email,
        role: session.user?.role,
      }}
    />
  );
}