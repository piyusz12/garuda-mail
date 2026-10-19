import { getServerSession } from 'next-auth';
import { redirect } from 'next/navigation';
import { authOptions } from '@/lib/auth';
import { getProtectedRouteForRole } from '@/lib/roles';

export default async function RootPage() {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    redirect('/login');
  }
  redirect(getProtectedRouteForRole(session.user.role));
}
