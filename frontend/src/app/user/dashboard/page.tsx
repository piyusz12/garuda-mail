import { requireUserSession } from '@/lib/authGuards';
import UserDashboardClient from './UserDashboardClient';

export default async function UserDashboardPage() {
  const session = await requireUserSession('/user/dashboard');

  return (
    <UserDashboardClient
      currentUser={{
        id: session.user.id,
        name: session.user.name,
        email: session.user.email,
        role: session.user.role || 'user',
        status: (session.user as any).status || 'active',
      }}
    />
  );
}
