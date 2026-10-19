/**
 * Garuda Mail — Centralized Authentication & Authorization Guards
 * Single source of truth for server component session checks and API route RBAC validation.
 */

import { getServerSession } from 'next-auth';
import { redirect } from 'next/navigation';
import { NextResponse } from 'next/server';
import { authOptions } from '@/lib/auth';
import { hasRoleAccess } from '@/lib/roles';
import type { Session } from 'next-auth';

/**
 * Server Component Guard: Asserts that the request has an active session with admin privileges.
 * If unauthorized, immediately redirects to the login page with callbackUrl and error flag.
 */
export async function requireAdminSession(callbackUrl = '/admin/dashboard'): Promise<Session> {
  const session = await getServerSession(authOptions);

  if (!session || !hasRoleAccess(session.user?.role, ['admin'])) {
    redirect(`/login?callbackUrl=${encodeURIComponent(callbackUrl)}&error=admin_required`);
  }

  return session;
}

/**
 * Server Component Guard: Asserts that the request has an active authenticated user session.
 * If unauthorized, redirects to the login page with callbackUrl.
 */
export async function requireUserSession(callbackUrl = '/user/dashboard'): Promise<Session> {
  const session = await getServerSession(authOptions);

  if (!session?.user) {
    redirect(`/login?callbackUrl=${encodeURIComponent(callbackUrl)}`);
  }

  return session;
}

/**
 * Route Handler Guard: Asserts that the API request has an active session with admin privileges.
 * Returns either the authorized session or a pre-formatted 401/403 NextResponse.
 */
export async function getAdminSessionOrReject(
  actionDescription = 'Administrator privileges required'
): Promise<
  | { authorized: true; session: Session }
  | { authorized: false; response: NextResponse }
> {
  const session = await getServerSession(authOptions);

  if (!session?.user) {
    return {
      authorized: false,
      response: NextResponse.json({ error: 'Unauthorized: Session required' }, { status: 401 }),
    };
  }

  const role = (session.user as { role?: string }).role;
  if (role !== 'admin') {
    return {
      authorized: false,
      response: NextResponse.json(
        { error: `Forbidden: ${actionDescription}` },
        { status: 403 }
      ),
    };
  }

  return { authorized: true, session };
}
