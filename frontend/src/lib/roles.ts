export type UserRole = 'admin' | 'officer' | 'user';

export const ROLE_LABELS: Record<UserRole, string> = {
  admin: 'Administrator',
  officer: 'Authorized User',
  user: 'Normal User',
};

export function normalizeUserRole(role?: string | null): UserRole {
  const normalized = String(role || '').toLowerCase();
  if (normalized === 'admin') return 'admin';
  if (normalized === 'officer') return 'officer';
  if (normalized === 'analyst' || normalized === 'authorized-user' || normalized === 'authorized_user') return 'user';
  return 'user';
}

export function getProtectedRouteForRole(role?: string): string {
  const normalized = normalizeUserRole(role);
  if (normalized === 'admin') return '/admin';
  if (normalized === 'officer') return '/officer';
  return '/inbox';
}

export function hasRoleAccess(role: string | undefined, allowedRoles: UserRole[]): boolean {
  return allowedRoles.includes(normalizeUserRole(role));
}