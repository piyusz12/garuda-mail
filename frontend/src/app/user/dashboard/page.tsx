import { Suspense } from 'react';
import { requireUserSession } from '@/lib/authGuards';
import UserDashboardClient from './UserDashboardClient';

export default async function UserDashboardPage() {
  const session = await requireUserSession('/user/dashboard');

  return (
    <Suspense fallback={<div className="p-8 text-center text-slate-400">Loading Dashboard...</div>}>
      <UserDashboardClient
        currentUser={{
          id: session.user.id,
          name: session.user.name,
          email: session.user.email,
          role: session.user.role || 'user',
          status: (session.user as any).status || 'active',
        }}
      />
    </Suspense>
  );
}
