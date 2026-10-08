import { getServerSession } from 'next-auth';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { authOptions } from '@/lib/auth';
import { hasRoleAccess } from '@/lib/roles';

export default async function OfficerPage() {
  const session = await getServerSession(authOptions);

  if (!session || !hasRoleAccess((session.user as any)?.role, ['officer', 'admin'])) {
    redirect('/login?callbackUrl=/officer');
  }

  return (
    <main className="min-h-screen bg-[var(--color-surface-0)] p-8">
      <div className="mx-auto max-w-5xl space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-[var(--color-accent)]">GARUDA OFFICER</p>
            <h1 className="mt-2 text-3xl font-bold text-[var(--color-text-primary)]">Authorized User Workspace</h1>
          </div>
          <Link href="/inbox" className="btn btn-secondary text-xs">Open inbox</Link>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <div className="card p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-[var(--color-text-dim)]">Mission</p>
            <h2 className="mt-3 text-2xl font-semibold text-[var(--color-text-primary)]">Case oversight</h2>
            <p className="mt-2 text-sm text-[var(--color-text-muted)]">Authorized users coordinate investigations, validate evidence, and make operational governance decisions.</p>
          </div>
          <div className="card p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-[var(--color-text-dim)]">Evidence Review</p>
            <h2 className="mt-3 text-2xl font-semibold text-[var(--color-text-primary)]">Trusted workflows</h2>
            <p className="mt-2 text-sm text-[var(--color-text-muted)]">This role is restricted to approved investigation and workflow actions, separate from admin-level configuration.</p>
          </div>
          <div className="card p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-[var(--color-text-dim)]">Governance</p>
            <h2 className="mt-3 text-2xl font-semibold text-[var(--color-text-primary)]">Protected access</h2>
            <p className="mt-2 text-sm text-[var(--color-text-muted)]">Unauthorized users are redirected away from this workspace and blocked by policy enforcement.</p>
          </div>
        </div>
      </div>
    </main>
  );
}