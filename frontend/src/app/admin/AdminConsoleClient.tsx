'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, ShieldAlert, RotateCcw, Trash2, Users, CheckCircle2,
  AlertTriangle, RefreshCw, Loader2, KeyRound, Lock, Search,
  UserCheck, ShieldCheck, X, FileText, Activity, Cpu, Network,
  Download, ArrowUpRight, Ban, Check, ArrowRightLeft, Sliders
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import Link from 'next/link';
import clsx from 'clsx';

export type AdminTab = 'overview' | 'users' | 'roles' | 'security' | 'sentinel' | 'audit' | 'settings';

interface UserDirectoryItem {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'officer' | 'user';
  status?: 'active' | 'suspended' | 'disabled';
  department?: string;
  avatarColor: string;
  createdAt: string;
}

interface AuditRecordItem {
  id: string;
  action: string;
  actorEmail?: string | null;
  actorRole?: string | null;
  targetEmail?: string | null;
  details?: string | null;
  status: 'SUCCESS' | 'FAILURE';
  createdAt: string;
}

interface AdminStats {
  totalUsers: number;
  activeUsers: number;
  suspendedUsers: number;
  adminCount: number;
  standardUserCount: number;
  totalAuditEvents: number;
  systemHealth: {
    authService: string;
    databasePersistence: string;
    fastApiBackend: string;
    cryptographicEngine: string;
    pqcReadiness: string;
  };
}

interface AdminConsoleClientProps {
  currentUser: {
    name?: string | null;
    email?: string | null;
    role?: string | null;
  };
  initialTab?: AdminTab;
}

export default function AdminConsoleClient({ currentUser, initialTab = 'overview' }: AdminConsoleClientProps) {
  const [activeTab, setActiveTab] = useState<AdminTab>(initialTab);
  const [users, setUsers] = useState<UserDirectoryItem[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditRecordItem[]>([]);
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  
  // Modals & Action States
  const [showResetModal, setShowResetModal] = useState(false);
  const [preserveAdmins, setPreserveAdmins] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [deletingEmail, setDeletingEmail] = useState<string | null>(null);

  // Status / Role change confirmation modal state
  const [confirmModal, setConfirmModal] = useState<{
    type: 'status' | 'role';
    email: string;
    newValue: string;
    title: string;
    message: string;
  } | null>(null);
  const [actionInProgress, setActionInProgress] = useState(false);

  // Notifications
  const [notification, setNotification] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  const showToast = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => {
      setNotification(null);
    }, 4500);
  };

  const fetchUsers = async () => {
    try {
      const res = await fetch('/api/admin/users');
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
      }
    } catch (err) {
      console.error('Failed to load user directory:', err);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      const res = await fetch('/api/admin/audit-logs?limit=150');
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data.logs || []);
      }
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/admin/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data.stats || null);
      }
    } catch (err) {
      console.error('Failed to load admin stats:', err);
    }
  };

  const loadAllData = async () => {
    setLoading(true);
    await Promise.all([fetchUsers(), fetchAuditLogs(), fetchStats()]);
    setLoading(false);
  };

  useEffect(() => {
    loadAllData();
  }, []);

  // Update account status (active vs suspended)
  const handleConfirmAction = async () => {
    if (!confirmModal) return;
    setActionInProgress(true);
    try {
      const { type, email, newValue } = confirmModal;
      const endpoint = '/api/admin/users';

      const payload = type === 'status'
        ? { action: 'update_status', email, status: newValue }
        : { action: 'update_role', email, role: newValue };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        showToast('success', data.message);
        setConfirmModal(null);
        await Promise.all([fetchUsers(), fetchAuditLogs(), fetchStats()]);
      } else {
        showToast('error', data.error || 'Operation failed');
      }
    } catch {
      showToast('error', 'Network error executing administrative action');
    } finally {
      setActionInProgress(false);
    }
  };

  // Reset all credentials
  const handleResetAll = async () => {
    try {
      setResetting(true);
      const res = await fetch('/api/admin/reset-credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'reset_all',
          purgeAll: !preserveAdmins,
          keepDefaultAdmins: preserveAdmins,
        }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        showToast('success', data.message || 'All login credentials deleted successfully.');
        setShowResetModal(false);
        await loadAllData();
      } else {
        showToast('error', data.error || 'Failed to reset credentials.');
      }
    } catch {
      showToast('error', 'Network error occurred while resetting credentials.');
    } finally {
      setResetting(false);
    }
  };

  // Delete single user
  const handleDeleteUser = async (email: string) => {
    if (!confirm(`Are you sure you want to delete credentials for ${email}?`)) {
      return;
    }

    try {
      setDeletingEmail(email);
      const res = await fetch('/api/admin/reset-credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'delete_user', email }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        showToast('success', `Credentials for ${email} successfully deleted.`);
        await loadAllData();
      } else {
        showToast('error', data.error || 'Failed to delete user.');
      }
    } catch {
      showToast('error', 'Network error occurred while deleting user.');
    } finally {
      setDeletingEmail(null);
    }
  };

  // Restore defaults
  const handleRestoreDefaults = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/admin/reset-credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'restore_defaults' }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        showToast('success', data.message || 'Default system demo accounts restored.');
        await loadAllData();
      } else {
        showToast('error', data.error || 'Failed to restore accounts.');
      }
    } catch {
      showToast('error', 'Network error while restoring accounts.');
    } finally {
      setLoading(false);
    }
  };

  const filteredUsers = users.filter((u) => {
    const q = search.toLowerCase().trim();
    return (
      u.name?.toLowerCase().includes(q) ||
      u.email?.toLowerCase().includes(q) ||
      u.role?.toLowerCase().includes(q) ||
      u.status?.toLowerCase().includes(q) ||
      u.department?.toLowerCase().includes(q)
    );
  });

  const adminCount = users.filter((u) => u.role === 'admin').length;
  const userCount = users.filter((u) => u.role === 'user').length;
  const activeCount = users.filter((u) => (u.status || 'active') === 'active').length;
  const suspendedCount = users.filter((u) => u.status === 'suspended').length;

  return (
    <AppShell
      title="GARUDA Administrative Control Plane"
      description="Tier-1 Root security governance, user authorization & forensic audit operations"
    >
      <div className="p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">

        {/* ── Toast Notifications ── */}
        <AnimatePresence>
          {notification && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className={clsx(
                'flex items-center justify-between p-3.5 rounded-xl border text-[13px] shadow-lg',
                notification.type === 'success'
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
              )}
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

        {/* ── Top Privileged Overview Banner ── */}
        <div className="p-5 rounded-2xl bg-gradient-to-r from-rose-950/30 via-purple-950/20 to-slate-900 border border-rose-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <ShieldAlert size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-rose-400">
                  Privileged Root Session
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  ROLE: ADMIN
                </span>
              </div>
              <h2 className="text-lg font-bold text-white">
                {currentUser?.name || 'Administrator'} ({currentUser?.email})
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => loadAllData()}
              disabled={loading}
              className="px-3 py-2 rounded-xl text-[12px] font-medium bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] text-[var(--color-text-secondary)] border border-[var(--color-border)] flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              <span>Refresh Telemetry</span>
            </button>
            <button
              onClick={handleRestoreDefaults}
              disabled={loading}
              title="Restore initial system demo accounts if desired"
              className="px-3 py-2 rounded-xl text-[12px] font-medium bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] text-slate-300 border border-[var(--color-border)] flex items-center gap-1.5 transition-colors"
            >
              <RotateCcw size={13} />
              <span className="hidden sm:inline">Restore Defaults</span>
            </button>
          </div>
        </div>

        {/* ── Navigation Tabs ── */}
        <div className="flex items-center gap-1 border-b border-[var(--color-border)] overflow-x-auto pb-1 text-xs">
          {[
            { id: 'overview', label: 'Admin Dashboard', icon: Shield },
            { id: 'users', label: 'User Management', icon: Users },
            { id: 'roles', label: 'Roles & RBAC', icon: ShieldCheck },
            { id: 'security', label: 'Security & Sentinel', icon: Activity },
            { id: 'audit', label: 'Audit Logs', icon: FileText },
            { id: 'settings', label: 'Settings & Reset', icon: Sliders },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as AdminTab)}
                className={clsx(
                  'flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium transition-all whitespace-nowrap',
                  active
                    ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30 font-semibold'
                    : 'text-slate-400 hover:text-white hover:bg-[var(--color-surface-2)]'
                )}
              >
                <Icon size={14} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* ── TAB 1: OVERVIEW & SYSTEM HEALTH ── */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="card p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)]">
                <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold block mb-1">
                  Total Users
                </span>
                <span className="text-2xl font-bold text-white">{users.length}</span>
                <p className="text-[11px] text-slate-400 mt-1">{activeCount} active • {suspendedCount} suspended</p>
              </div>

              <div className="card p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)]">
                <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold block mb-1">
                  Administrators
                </span>
                <span className="text-2xl font-bold text-rose-400">{adminCount}</span>
                <p className="text-[11px] text-slate-400 mt-1">Tier-1 Root privileged</p>
              </div>

              <div className="card p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)]">
                <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold block mb-1">
                  Audit Events
                </span>
                <span className="text-2xl font-bold text-indigo-400">{auditLogs.length}</span>
                <p className="text-[11px] text-slate-400 mt-1">Recorded audit ledger</p>
              </div>

              <div className="card p-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)]">
                <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold block mb-1">
                  FastAPI Backend
                </span>
                <span className="text-2xl font-bold text-emerald-400">
                  {stats?.systemHealth?.fastApiBackend === 'connected' ? 'ONLINE' : 'ACTIVE'}
                </span>
                <p className="text-[11px] text-emerald-400/80 mt-1">Port 8000 Sentinel</p>
              </div>
            </div>

            {/* System Health Breakdown */}
            <div className="card p-5 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Activity size={16} className="text-sky-400" />
                Service Health & Architecture Status
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Authentication Guard</span>
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">NextAuth JWT Session</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 font-bold">HEALTHY</span>
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Database Persistence</span>
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">Prisma Multi-Tier Store</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 font-bold">OPERATIONAL</span>
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Zero-Knowledge Invariant</span>
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">Web Crypto E2EE V2</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 font-bold">ENFORCED</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── TAB 2: USER MANAGEMENT ── */}
        {activeTab === 'users' && (
          <div className="card rounded-2xl overflow-hidden border border-[var(--color-border)] bg-[var(--color-surface-1)]">
            <div className="p-4 sm:p-5 border-b border-[var(--color-border)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Users size={16} className="text-rose-400" />
                <h3 className="text-sm font-bold text-white">User Accounts &amp; Access Controls</h3>
                <span className="text-xs text-slate-400">({filteredUsers.length} total)</span>
              </div>

              <div className="relative w-full sm:w-72">
                <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Filter by name, email, role, status..."
                  className="w-full h-8 pl-9 pr-3 text-xs rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-white placeholder:text-slate-500 focus:outline-none focus:border-rose-400"
                />
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-2)] text-slate-400 text-[10px] uppercase tracking-wider font-semibold">
                    <th className="py-3 px-4">User</th>
                    <th className="py-3 px-4">Email</th>
                    <th className="py-3 px-4">Role</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Department</th>
                    <th className="py-3 px-4 text-right">Administrative Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border-subtle)] text-slate-300">
                  {filteredUsers.map((u) => {
                    const isCurrentUser = currentUser.email?.toLowerCase().trim() === u.email.toLowerCase().trim();
                    const isMasterAdmin = u.email.toLowerCase().trim() === 'admin@garudamail.local';
                    const isSuspended = u.status === 'suspended';

                    return (
                      <tr key={u.id} className="hover:bg-[var(--color-surface-2)] transition-colors">
                        <td className="py-3 px-4 flex items-center gap-2.5 font-medium text-white">
                          <div
                            className="w-7 h-7 rounded-full flex items-center justify-center font-bold text-[11px] text-white flex-shrink-0"
                            style={{ backgroundColor: u.avatarColor || '#38BDF8' }}
                          >
                            {u.name[0].toUpperCase()}
                          </div>
                          <span>{u.name}</span>
                          {isCurrentUser && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                              YOU
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-[11px] text-slate-400">{u.email}</td>
                        <td className="py-3 px-4">
                          <span
                            className={clsx(
                              'px-2 py-0.5 rounded-full text-[10px] font-semibold border uppercase',
                              u.role === 'admin'
                                ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                                : 'bg-sky-500/15 text-sky-300 border-sky-500/30'
                            )}
                          >
                            {u.role}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={clsx(
                              'px-2 py-0.5 rounded-full text-[10px] font-semibold border uppercase flex items-center gap-1 w-fit',
                              isSuspended
                                ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                                : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                            )}
                          >
                            <span className={clsx('w-1.5 h-1.5 rounded-full', isSuspended ? 'bg-rose-400' : 'bg-emerald-400')} />
                            {isSuspended ? 'SUSPENDED' : 'ACTIVE'}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-[11px]">{u.department || 'Cryptographic SOC'}</td>
                        <td className="py-3 px-4 text-right space-x-1.5">
                          {/* Suspend / Activate Button */}
                          {!isMasterAdmin && !isCurrentUser && (
                            <button
                              onClick={() => {
                                setConfirmModal({
                                  type: 'status',
                                  email: u.email,
                                  newValue: isSuspended ? 'active' : 'suspended',
                                  title: isSuspended ? 'Reactivate Account' : 'Suspend Account',
                                  message: isSuspended
                                    ? `Are you sure you want to reactivate access for ${u.email}?`
                                    : `Are you sure you want to suspend access for ${u.email}? They will be blocked from logging in.`,
                                });
                              }}
                              className={clsx(
                                'px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-colors border',
                                isSuspended
                                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/25'
                                  : 'bg-amber-500/15 text-amber-300 border-amber-500/30 hover:bg-amber-500/25'
                              )}
                            >
                              {isSuspended ? 'Reactivate' : 'Suspend'}
                            </button>
                          )}

                          {/* Role Toggle Button */}
                          {!isMasterAdmin && !isCurrentUser && (
                            <button
                              onClick={() => {
                                const targetRole = u.role === 'admin' ? 'user' : 'admin';
                                setConfirmModal({
                                  type: 'role',
                                  email: u.email,
                                  newValue: targetRole,
                                  title: targetRole === 'admin' ? 'Promote to Administrator' : 'Demote to Normal User',
                                  message: `Are you sure you want to change the role of ${u.email} to "${targetRole.toUpperCase()}"?`,
                                });
                              }}
                              className="px-2.5 py-1 rounded-lg text-[11px] font-medium bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] text-slate-200 border border-[var(--color-border)] transition-colors"
                            >
                              {u.role === 'admin' ? 'Demote to User' : 'Make Admin'}
                            </button>
                          )}

                          {/* Delete Credentials */}
                          {!isMasterAdmin && !isCurrentUser && (
                            <button
                              onClick={() => handleDeleteUser(u.email)}
                              disabled={deletingEmail === u.email}
                              className="px-2 py-1 rounded-lg text-[11px] text-rose-400 hover:bg-rose-500/15 border border-transparent hover:border-rose-500/30 transition-colors"
                              title="Delete user credentials"
                            >
                              <Trash2 size={13} />
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── TAB 3: ROLES & RBAC ── */}
        {activeTab === 'roles' && (
          <div className="card p-6 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-6">
            <div className="border-b border-[var(--color-border-subtle)] pb-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <ShieldCheck size={18} className="text-purple-400" />
                Role-Based Access Control (RBAC) Architecture
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Deterministic server-side authorization boundaries enforced at middleware and API handlers.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-rose-500/20 space-y-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 uppercase">
                  ROLE: ADMIN
                </span>
                <p className="font-semibold text-white">Privileged System Administrator</p>
                <ul className="text-slate-300 space-y-1 list-disc list-inside text-[11px]">
                  <li>Full user directory oversight & account status control.</li>
                  <li>Can suspend, reactivate, or delete user credentials.</li>
                  <li>Can promote users to admin or demote roles.</li>
                  <li>Access to complete system audit logs & security telemetry.</li>
                  <li><b>Zero-Knowledge Guarantee:</b> Cannot decrypt user E2EE messages.</li>
                </ul>
              </div>

              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-sky-500/20 space-y-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30 uppercase">
                  ROLE: USER
                </span>
                <p className="font-semibold text-white">Standard Communicator</p>
                <ul className="text-slate-300 space-y-1 list-disc list-inside text-[11px]">
                  <li>Send and receive end-to-end encrypted emails (RSA-OAEP + AES-GCM).</li>
                  <li>Digital signature creation and verification (RSA-PSS).</li>
                  <li>Own key vault management & passphrase protection.</li>
                  <li>Inspect peer public keys and presence status.</li>
                  <li>Strictly prohibited from administrative APIs and other users&apos; data.</li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* ── TAB 4: SECURITY & SENTINEL ── */}
        {activeTab === 'security' && (
          <div className="card p-6 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-6">
            <div className="border-b border-[var(--color-border-subtle)] pb-4 flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Activity size={18} className="text-indigo-400" />
                  GARUDA Sentinel Security Oversight
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Deterministic cryptographic risk scoring and post-quantum readiness inspection
                </p>
              </div>
              <Link
                href="/dashboard"
                className="flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300 font-semibold"
              >
                Full Forensic Dashboard <ArrowUpRight size={13} />
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Authoritative CRS Engine</span>
                <span className="text-lg font-bold text-rose-400 block">Deterministic Policy Engine</span>
                <p className="text-[11px] text-slate-400">Rules calculate scores strictly from observed network evidence.</p>
              </div>
              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">AI Anomaly Isolation</span>
                <span className="text-lg font-bold text-purple-400 block">Anomaly Telemetry Active</span>
                <p className="text-[11px] text-slate-400">AI scores remain separate and cannot downgrade security findings.</p>
              </div>
              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Post-Quantum Migration</span>
                <span className="text-lg font-bold text-teal-400 block">CBOM &amp; PQC Audit Ready</span>
                <p className="text-[11px] text-slate-400">Cryptographic inventory tracks classical vs quantum-vulnerable ciphers.</p>
              </div>
            </div>
          </div>
        )}

        {/* ── TAB 5: AUDIT LOGS ── */}
        {activeTab === 'audit' && (
          <div className="card rounded-2xl overflow-hidden border border-[var(--color-border)] bg-[var(--color-surface-1)]">
            <div className="p-4 sm:p-5 border-b border-[var(--color-border)] flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <FileText size={16} className="text-indigo-400" />
                  System Audit Ledger
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">Immutable record of security and administrative operations</p>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                {auditLogs.length} Events
              </span>
            </div>

            <div className="overflow-x-auto max-h-[500px]">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="sticky top-0 bg-[var(--color-surface-2)] border-b border-[var(--color-border)] text-slate-400 text-[10px] uppercase font-semibold">
                  <tr>
                    <th className="py-2.5 px-4">Timestamp</th>
                    <th className="py-2.5 px-4">Action</th>
                    <th className="py-2.5 px-4">Actor</th>
                    <th className="py-2.5 px-4">Target</th>
                    <th className="py-2.5 px-4">Details</th>
                    <th className="py-2.5 px-4">Outcome</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border-subtle)] text-slate-300">
                  {auditLogs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        No audit events recorded yet.
                      </td>
                    </tr>
                  ) : (
                    auditLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-[var(--color-surface-2)] transition-colors">
                        <td className="py-2.5 px-4 font-mono text-[10px] text-slate-400 whitespace-nowrap">
                          {new Date(log.createdAt).toLocaleString()}
                        </td>
                        <td className="py-2.5 px-4 font-mono text-[11px] font-bold text-sky-300">
                          {log.action}
                        </td>
                        <td className="py-2.5 px-4 text-slate-300 text-[11px]">
                          {log.actorEmail || 'system'}
                        </td>
                        <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                          {log.targetEmail || '—'}
                        </td>
                        <td className="py-2.5 px-4 text-slate-300 text-[11px] max-w-xs truncate">
                          {log.details || '—'}
                        </td>
                        <td className="py-2.5 px-4">
                          <span
                            className={clsx(
                              'px-1.5 py-0.5 rounded text-[9px] font-bold uppercase',
                              log.status === 'SUCCESS'
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : 'bg-rose-500/20 text-rose-300'
                            )}
                          >
                            {log.status}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── TAB 6: SETTINGS & DANGER ZONE ── */}
        {activeTab === 'settings' && (
          <div className="space-y-6">
            <div className="card p-6 rounded-2xl border border-rose-500/30 bg-gradient-to-br from-rose-950/20 via-[var(--color-surface-1)] to-[var(--color-surface-1)] space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="p-1 rounded bg-rose-500/20 text-rose-400">
                      <KeyRound size={16} />
                    </span>
                    <h3 className="text-base font-bold text-white">
                      Credentials &amp; Active Sessions Reset
                    </h3>
                  </div>
                  <p className="text-xs text-slate-400 max-w-2xl">
                    Purge all registered user login credentials, password hashes, and active authentication sessions.
                    Restores the credential registry to a clean baseline.
                  </p>
                </div>

                <button
                  id="admin-reset-credentials-btn"
                  type="button"
                  onClick={() => setShowResetModal(true)}
                  className="flex-shrink-0 h-10 px-4 flex items-center justify-center gap-2 text-xs font-semibold rounded-xl bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-600/25 active:scale-[0.98] transition-all cursor-pointer border border-rose-400/30"
                >
                  <RotateCcw size={15} />
                  <span>Reset All Login Credentials</span>
                </button>
              </div>
            </div>
          </div>
        )}

      </div>

      {/* ── Action Confirmation Modal (Status or Role) ── */}
      <AnimatePresence>
        {confirmModal && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="card p-6 rounded-2xl max-w-md w-full border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-4 shadow-2xl"
            >
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <AlertTriangle size={18} className="text-amber-400" />
                {confirmModal.title}
              </h3>
              <p className="text-xs text-slate-300">
                {confirmModal.message}
              </p>
              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setConfirmModal(null)}
                  disabled={actionInProgress}
                  className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleConfirmAction}
                  disabled={actionInProgress}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-all flex items-center gap-1.5"
                >
                  {actionInProgress && <Loader2 size={13} className="animate-spin" />}
                  Confirm Operation
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Reset All Credentials Modal ── */}
      <AnimatePresence>
        {showResetModal && (
          <div className="fixed inset-0 bg-black/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="card p-6 rounded-2xl max-w-md w-full border border-rose-500/40 bg-[var(--color-surface-1)] space-y-4 shadow-2xl"
            >
              <div className="flex items-center gap-2.5 text-rose-400">
                <AlertTriangle size={20} />
                <h3 className="text-base font-bold text-white">Reset All Credentials</h3>
              </div>
              <p className="text-xs text-slate-300">
                This will purge all user accounts, password hashes, and active sessions across the database and in-memory stores.
              </p>
              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={preserveAdmins}
                  onChange={(e) => setPreserveAdmins(e.target.checked)}
                  className="rounded border-[var(--color-border)]"
                />
                <span>Preserve active administrator ({currentUser.email})</span>
              </label>
              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowResetModal(false)}
                  disabled={resetting}
                  className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleResetAll}
                  disabled={resetting}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-all flex items-center gap-1.5"
                >
                  {resetting && <Loader2 size={13} className="animate-spin" />}
                  Execute Reset
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </AppShell>
  );
}
