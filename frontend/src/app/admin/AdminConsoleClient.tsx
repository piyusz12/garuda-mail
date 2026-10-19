'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, ShieldAlert, RotateCcw, Trash2, Users, CheckCircle2,
  AlertTriangle, RefreshCw, Loader2, KeyRound, Lock, Search,
  UserCheck, ShieldCheck, X
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';

interface UserDirectoryItem {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'officer' | 'user';
  department?: string;
  avatarColor: string;
  createdAt: string;
}

interface AdminConsoleClientProps {
  currentUser: {
    name?: string | null;
    email?: string | null;
    role?: string | null;
  };
}

export default function AdminConsoleClient({ currentUser }: AdminConsoleClientProps) {
  const [users, setUsers] = useState<UserDirectoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  
  // Reset dialog state
  const [showResetModal, setShowResetModal] = useState(false);
  const [preserveAdmins, setPreserveAdmins] = useState(true);
  const [resetting, setResetting] = useState(false);
  const [deletingEmail, setDeletingEmail] = useState<string | null>(null);

  // Notifications
  const [notification, setNotification] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/users');
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
      }
    } catch (err) {
      console.error('Failed to load user directory:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const showToast = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => {
      setNotification(null);
    }, 4500);
  };

  const handleResetAll = async () => {
    try {
      setResetting(true);
      const res = await fetch('/api/admin/reset-credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'reset_all',
          keepDefaultAdmins: preserveAdmins,
        }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        showToast('success', data.message || 'All login credentials and active sessions deleted successfully.');
        setShowResetModal(false);
        await fetchUsers();
      } else {
        showToast('error', data.error || 'Failed to reset credentials.');
      }
    } catch {
      showToast('error', 'Network error occurred while resetting credentials.');
    } finally {
      setResetting(false);
    }
  };

  const handleDeleteUser = async (email: string) => {
    if (!confirm(`Are you sure you want to delete credentials for ${email}?`)) {
      return;
    }

    try {
      setDeletingEmail(email);
      const res = await fetch('/api/admin/reset-credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'delete_user',
          email,
        }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        showToast('success', `Credentials for ${email} successfully deleted.`);
        await fetchUsers();
      } else {
        showToast('error', data.error || 'Failed to delete user.');
      }
    } catch {
      showToast('error', 'Network error occurred while deleting user.');
    } finally {
      setDeletingEmail(null);
    }
  };

  const filteredUsers = users.filter((u) => {
    const q = search.toLowerCase().trim();
    return (
      u.name?.toLowerCase().includes(q) ||
      u.email?.toLowerCase().includes(q) ||
      u.role?.toLowerCase().includes(q) ||
      u.department?.toLowerCase().includes(q)
    );
  });

  const adminCount = users.filter((u) => u.role === 'admin').length;
  const userCount = users.filter((u) => u.role === 'user').length;

  return (
    <AppShell
      title="Administration & Governance"
      description="Privileged access controls, identity directory & credential management"
    >
      <div className="p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">
        {/* Toast Notification */}
        <AnimatePresence>
          {notification && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className={`flex items-center justify-between p-3.5 rounded-xl border text-[13px] shadow-lg ${
                notification.type === 'success'
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
              }`}
            >
              <div className="flex items-center gap-2">
                {notification.type === 'success' ? (
                  <CheckCircle2 size={16} className="text-emerald-400 flex-shrink-0" />
                ) : (
                  <AlertTriangle size={16} className="text-rose-400 flex-shrink-0" />
                )}
                <span>{notification.message}</span>
              </div>
              <button
                onClick={() => setNotification(null)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X size={14} />
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── Top Privileged Overview ── */}
        <div className="p-5 rounded-2xl bg-gradient-to-r from-rose-950/30 via-purple-950/20 to-slate-900 border border-rose-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <ShieldAlert size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-rose-400">
                  Privileged Admin Session
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  Tier-1 Root
                </span>
              </div>
              <h2 className="text-lg font-bold text-white">
                {currentUser?.name || 'Administrator'} ({currentUser?.email})
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => fetchUsers()}
              disabled={loading}
              className="px-3 py-2 rounded-xl text-[12px] font-medium bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] text-[var(--color-text-secondary)] border border-[var(--color-border)] flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* ── Metric Cards ── */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="card p-4 flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
              <Users size={18} />
            </div>
            <div>
              <p className="text-[11px] text-[var(--color-text-muted)] uppercase tracking-wider font-semibold">
                Total Identities
              </p>
              <p className="text-xl font-bold text-[var(--color-text-primary)]">
                {loading ? '...' : users.length}
              </p>
            </div>
          </div>

          <div className="card p-4 flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <ShieldCheck size={18} />
            </div>
            <div>
              <p className="text-[11px] text-[var(--color-text-muted)] uppercase tracking-wider font-semibold">
                Administrators
              </p>
              <p className="text-xl font-bold text-purple-400">
                {loading ? '...' : adminCount}
              </p>
            </div>
          </div>

          <div className="card p-4 flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <UserCheck size={18} />
            </div>
            <div>
              <p className="text-[11px] text-[var(--color-text-muted)] uppercase tracking-wider font-semibold">
                Normal Accounts
              </p>
              <p className="text-xl font-bold text-emerald-400">
                {loading ? '...' : userCount}
              </p>
            </div>
          </div>
        </div>

        {/* ── Danger Zone: Admin-Only Reset Credentials Button ── */}
        <div className="card p-5 sm:p-6 rounded-2xl border border-rose-500/30 bg-gradient-to-br from-rose-950/20 via-[var(--color-surface-1)] to-[var(--color-surface-1)] space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="p-1 rounded bg-rose-500/20 text-rose-400">
                  <KeyRound size={14} />
                </span>
                <h3 className="text-base font-bold text-white">
                  Credentials &amp; Active Sessions Governance
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-500/15 border border-rose-500/30 text-rose-400 uppercase">
                  Admin Only
                </span>
              </div>
              <p className="text-[12px] text-[var(--color-text-muted)] max-w-2xl">
                Delete and purge all registered user login credentials, password hashes, and active authentication sessions.
                This action restores the authentication directory to a clean baseline so all users can register or log in fresh.
              </p>
            </div>

            {/* THE RESET BUTTON: Provided After Login As Admin Only */}
            <button
              id="admin-reset-credentials-btn"
              type="button"
              onClick={() => setShowResetModal(true)}
              className="flex-shrink-0 h-10 px-4 flex items-center justify-center gap-2 text-[13px] font-semibold rounded-xl bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-600/25 active:scale-[0.98] transition-all cursor-pointer border border-rose-400/30"
            >
              <RotateCcw size={15} />
              <span>Reset All Login Credentials</span>
            </button>
          </div>
        </div>

        {/* ── User Directory Table ── */}
        <div className="card rounded-2xl overflow-hidden border border-[var(--color-border)]">
          <div className="p-4 sm:p-5 border-b border-[var(--color-border)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[var(--color-surface-1)]">
            <div className="flex items-center gap-2">
              <Users size={16} className="text-[var(--color-accent)]" />
              <h3 className="text-[14px] font-bold text-[var(--color-text-primary)]">
                Active User Credentials Directory
              </h3>
              <span className="text-[11px] text-[var(--color-text-muted)]">
                ({filteredUsers.length} accounts)
              </span>
            </div>

            {/* Search Input */}
            <div className="relative w-full sm:w-64">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by name, email, role..."
                className="w-full h-8 pl-9 pr-3 text-[12px] rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-white placeholder:text-slate-500 focus:outline-none focus:border-[var(--color-accent)]"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-2)]/50 text-[var(--color-text-muted)] uppercase tracking-wider text-[10px]">
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4">Email</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Department</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {loading ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-400">
                      <div className="flex items-center justify-center gap-2">
                        <Loader2 size={16} className="animate-spin text-sky-400" />
                        <span>Loading user credentials directory...</span>
                      </div>
                    </td>
                  </tr>
                ) : filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-400">
                      No user accounts found matching your query.
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map((u) => {
                    const isSelf = u.email === currentUser?.email;
                    return (
                      <tr
                        key={u.id + u.email}
                        className="hover:bg-[var(--color-surface-2)]/60 transition-colors"
                      >
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2.5">
                            <div
                              className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-white shadow-sm flex-shrink-0"
                              style={{ backgroundColor: u.avatarColor || '#38BDF8' }}
                            >
                              {u.name?.charAt(0).toUpperCase() || 'U'}
                            </div>
                            <span className="font-medium text-white truncate">
                              {u.name}
                              {isSelf && (
                                <span className="ml-1.5 text-[10px] text-sky-400 font-mono">(You)</span>
                              )}
                            </span>
                          </div>
                        </td>

                        <td className="py-3 px-4 font-mono text-[11px] text-slate-300">
                          {u.email}
                        </td>

                        <td className="py-3 px-4">
                          {u.role === 'admin' ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-500/15 border border-purple-500/30 text-purple-300">
                              <Shield size={10} /> Admin
                            </span>
                          ) : u.role === 'officer' ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-sky-500/15 border border-sky-500/30 text-sky-300">
                              <ShieldCheck size={10} /> Officer
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 border border-emerald-500/30 text-emerald-300">
                              <UserCheck size={10} /> User
                            </span>
                          )}
                        </td>

                        <td className="py-3 px-4 text-slate-400">
                          {u.department || 'Cryptographic SOC'}
                        </td>

                        <td className="py-3 px-4">
                          <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                            Active
                          </span>
                        </td>

                        <td className="py-3 px-4 text-right">
                          {isSelf ? (
                            <span className="text-[11px] text-slate-500 italic">Master Root</span>
                          ) : (
                            <button
                              type="button"
                              onClick={() => handleDeleteUser(u.email)}
                              disabled={deletingEmail === u.email}
                              title="Delete user credentials"
                              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 border border-transparent hover:border-rose-500/20 transition-colors"
                            >
                              {deletingEmail === u.email ? (
                                <Loader2 size={13} className="animate-spin" />
                              ) : (
                                <Trash2 size={13} />
                              )}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Security Architecture Summary ── */}
        <div className="grid gap-4 md:grid-cols-3">
          <div className="card p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-[var(--color-text-dim)]">Identity &amp; Access</p>
            <h4 className="mt-2 text-lg font-semibold text-[var(--color-text-primary)]">RBAC Enforced</h4>
            <p className="mt-1 text-xs text-[var(--color-text-muted)]">
              Authentication and credential revocation policies are verified on every protected API endpoint and server route.
            </p>
          </div>
          <div className="card p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-[var(--color-text-dim)]">Security Controls</p>
            <h4 className="mt-2 text-lg font-semibold text-[var(--color-text-primary)]">Audit-Ready</h4>
            <p className="mt-1 text-xs text-[var(--color-text-muted)]">
              Privileged credential reset routines execute server-side with cryptographic hash validation and session invalidation.
            </p>
          </div>
          <div className="card p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-[var(--color-text-dim)]">Session Lifecycles</p>
            <h4 className="mt-2 text-lg font-semibold text-[var(--color-text-primary)]">Ephemeral Purging</h4>
            <p className="mt-1 text-xs text-[var(--color-text-muted)]">
              Full reset purges in-memory caches, temporary SQLite user registries, and client authentication tokens.
            </p>
          </div>
        </div>
      </div>

      {/* ── Reset Confirmation Modal ── */}
      <AnimatePresence>
        {showResetModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-md card bg-[var(--color-surface-1)] border border-rose-500/30 rounded-2xl p-6 shadow-2xl space-y-4"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
                  <AlertTriangle size={20} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">
                    Confirm Credentials Reset
                  </h3>
                  <p className="text-[11px] text-rose-400">
                    Irreversible administrative operation
                  </p>
                </div>
              </div>

              <p className="text-[12px] text-slate-300 leading-relaxed">
                You are about to delete all login credentials and purge active user sessions across the system.
                Users will need to re-register or use master administrative credentials to log in fresh.
              </p>

              <label className="flex items-center gap-2 p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] cursor-pointer text-[12px]">
                <input
                  type="checkbox"
                  checked={preserveAdmins}
                  onChange={(e) => setPreserveAdmins(e.target.checked)}
                  className="rounded border-slate-600 text-rose-500 focus:ring-rose-500"
                />
                <span className="text-slate-200">
                  Preserve default root administrators (recommended)
                </span>
              </label>

              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowResetModal(false)}
                  disabled={resetting}
                  className="px-4 py-2 rounded-xl text-[12px] font-medium bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  id="confirm-admin-reset-btn"
                  type="button"
                  onClick={handleResetAll}
                  disabled={resetting}
                  className="px-4 py-2 rounded-xl text-[12px] font-semibold bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-600/30 flex items-center gap-2 transition-colors"
                >
                  {resetting ? (
                    <>
                      <Loader2 size={14} className="animate-spin" />
                      Deleting Credentials...
                    </>
                  ) : (
                    <>
                      <RotateCcw size={14} />
                      Yes, Delete All Credentials
                    </>
                  )}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </AppShell>
  );
}
