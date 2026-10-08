import { getServerSession } from 'next-auth';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { authOptions } from '@/lib/auth';
import { hasRoleAccess } from '@/lib/roles';

export default async function AdminPage() {
  const session = await getServerSession(authOptions);

  if (!session || !hasRoleAccess((session.user as any)?.role, ['admin'])) {
    redirect('/login?callbackUrl=/admin');
  }

  return (
    <main className="min-h-screen bg-[var(--color-surface-0)] p-8">
      <div className="mx-auto max-w-5xl space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-[var(--color-accent)]">GARUDA ADMIN</p>
            <h1 className="mt-2 text-3xl font-bold text-[var(--color-text-primary)]">Administration Console</h1>
          </div>
          <Link href="/inbox" className="btn btn-secondary text-xs">Return to inbox</Link>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <div className="card p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-[var(--color-text-dim)]">Identity & Access</p>
            <h2 className="mt-3 text-2xl font-semibold text-[var(--color-text-primary)]">RBAC enforced</h2>
            <p className="mt-2 text-sm text-[var(--color-text-muted)]">Role assignment is resolved by the backend session and route policy, not by the frontend.</p>
          </div>
          <div className="card p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-[var(--color-text-dim)]">Security Controls</p>
            <h2 className="mt-3 text-2xl font-semibold text-[var(--color-text-primary)]">Audit-ready</h2>
            <p className="mt-2 text-sm text-[var(--color-text-muted)]">Administrative actions are isolated from normal user workflows and protected by backend authorization checks.</p>
          </div>
          <div className="card p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-[var(--color-text-dim)]">Operations</p>
            <h2 className="mt-3 text-2xl font-semibold text-[var(--color-text-primary)]">Full control</h2>
            <p className="mt-2 text-sm text-[var(--color-text-muted)]">Admins can manage policies, monitor investigations, and approve privileged workflows.</p>
          </div>
        </div>
      </div>
    </main>
  );
}