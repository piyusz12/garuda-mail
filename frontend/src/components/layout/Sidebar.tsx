'use client';

import Link from 'next/link';
import { useState, useEffect } from 'react';
import { usePathname } from 'next/navigation';
import { useSession } from 'next-auth/react';
import {
  Inbox, Send, FileEdit, Star, Archive, Trash2,
  LayoutDashboard, Upload, Network, AlertTriangle, Shield,
  Award, Brain, Search as SearchIcon, FileText, Settings, Layers,
  ChevronLeft, ChevronRight, Plus, Mail, Cpu, Activity, X, FlaskConical,
  ShieldAlert, Users,
} from 'lucide-react';
import clsx from 'clsx';

const userNav = [
  { name: 'My Dashboard', href: '/user/dashboard', icon: LayoutDashboard, color: 'text-sky-400', activeBg: 'bg-sky-500/15 border-sky-500/30 text-sky-400' },
  { name: 'Inbox', href: '/inbox', icon: Inbox, countKey: 'inbox' as const, color: 'text-sky-400', activeBg: 'bg-sky-500/15 border-sky-500/30 text-sky-400' },
  { name: 'Sent', href: '/sent', icon: Send, color: 'text-indigo-400', activeBg: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-400' },
  { name: 'Drafts', href: '/drafts', icon: FileEdit, countKey: 'drafts' as const, color: 'text-amber-400', activeBg: 'bg-amber-500/15 border-amber-500/30 text-amber-400' },
  { name: 'Starred', href: '/starred', icon: Star, color: 'text-yellow-400', activeBg: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-400' },
  { name: 'Contacts', href: '/user/contacts', icon: Users, color: 'text-emerald-400', activeBg: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400' },
  { name: 'Security Posture', href: '/user/security', icon: Shield, color: 'text-cyan-400', activeBg: 'bg-cyan-500/15 border-cyan-500/30 text-cyan-400' },
  { name: 'Key Vault', href: '/crypto', icon: ShieldAlert, color: 'text-emerald-400', activeBg: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400' },
  { name: 'My Reports', href: '/user/reports', icon: FileText, color: 'text-slate-300', activeBg: 'bg-slate-500/15 border-slate-500/30 text-slate-200' },
  { name: 'Settings', href: '/settings', icon: Settings, color: 'text-slate-400', activeBg: 'bg-slate-500/15 border-slate-500/30 text-slate-300' },
];

const adminNav = [
  { name: 'Admin Dashboard', href: '/admin/dashboard', icon: ShieldAlert, color: 'text-rose-400', activeBg: 'bg-rose-500/15 border-rose-500/30 text-rose-300' },
  { name: 'User Management', href: '/admin/users', icon: Users, color: 'text-rose-400', activeBg: 'bg-rose-500/15 border-rose-500/30 text-rose-300' },
  { name: 'Roles & RBAC', href: '/admin/roles', icon: Shield, color: 'text-purple-400', activeBg: 'bg-purple-500/15 border-purple-500/30 text-purple-400' },
  { name: 'Audit Logs', href: '/admin/audit-logs', icon: FileText, color: 'text-indigo-400', activeBg: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-400' },
];

const emailNav = [
  { name: 'Inbox', href: '/inbox', icon: Inbox, countKey: 'inbox' as const, color: 'text-sky-400', activeBg: 'bg-sky-500/15 border-sky-500/30 text-sky-400' },
  { name: 'Sent', href: '/sent', icon: Send, color: 'text-indigo-400', activeBg: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-400' },
  { name: 'Drafts', href: '/drafts', icon: FileEdit, countKey: 'drafts' as const, color: 'text-amber-400', activeBg: 'bg-amber-500/15 border-amber-500/30 text-amber-400' },
  { name: 'Starred', href: '/starred', icon: Star, color: 'text-yellow-400', activeBg: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-400' },
  { name: 'Archive', href: '/archive', icon: Archive, color: 'text-emerald-400', activeBg: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400' },
  { name: 'Trash', href: '/trash', icon: Trash2, color: 'text-rose-400', activeBg: 'bg-rose-500/15 border-rose-500/30 text-rose-400' },
];

const systemNav = [
  { name: 'Overview', href: '/dashboard', icon: LayoutDashboard, color: 'text-sky-400', activeBg: 'bg-sky-500/15 border-sky-500/30 text-sky-400' },
  { name: 'AI Fabric', href: '/fabric', icon: Cpu, color: 'text-purple-400', activeBg: 'bg-purple-500/15 border-purple-500/30 text-purple-400' },
  { name: 'Autonomous Ops', href: '/operations', icon: Activity, color: 'text-cyan-400', activeBg: 'bg-cyan-500/15 border-cyan-500/30 text-cyan-400' },
  { name: 'GARUDA Lab', href: '/lab', icon: FlaskConical, color: 'text-amber-400', activeBg: 'bg-amber-500/15 border-amber-500/30 text-amber-300' },
  { name: 'Analysis', href: '/analysis', icon: Upload, color: 'text-indigo-400', activeBg: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-400' },
  { name: 'Sessions', href: '/sessions', icon: Network, color: 'text-blue-400', activeBg: 'bg-blue-500/15 border-blue-500/30 text-blue-400' },
  { name: 'Findings', href: '/findings', icon: AlertTriangle, color: 'text-amber-400', activeBg: 'bg-amber-500/15 border-amber-500/30 text-amber-400' },
  { name: 'Crypto Posture', href: '/crypto', icon: Shield, color: 'text-emerald-400', activeBg: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400' },
  { name: 'Certificates & CA', href: '/certificates', icon: Award, color: 'text-rose-400', activeBg: 'bg-rose-500/15 border-rose-500/30 text-rose-400' },
  { name: 'AI Anomalies', href: '/anomalies', icon: Brain, color: 'text-fuchsia-400', activeBg: 'bg-fuchsia-500/15 border-fuchsia-500/30 text-fuchsia-400' },
  { name: 'Investigations', href: '/investigations', icon: SearchIcon, color: 'text-violet-400', activeBg: 'bg-violet-500/15 border-violet-500/30 text-violet-400' },
  { name: 'CBOM', href: '/cbom', icon: Layers, color: 'text-teal-400', activeBg: 'bg-teal-500/15 border-teal-500/30 text-teal-400' },
  { name: 'Reports', href: '/reports', icon: FileText, color: 'text-slate-300', activeBg: 'bg-slate-500/15 border-slate-500/30 text-slate-200' },
  { name: 'Settings', href: '/settings', icon: Settings, color: 'text-slate-400', activeBg: 'bg-slate-500/15 border-slate-500/30 text-slate-300' },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export default function Sidebar({ collapsed, onToggle, mobileOpen, onCloseMobile }: SidebarProps) {
  const pathname = usePathname();
  const { data: session } = useSession();
  const isAdmin = session?.user?.role === 'admin';
  const [unreadCounts, setUnreadCounts] = useState<Record<string, number>>({ inbox: 0, drafts: 0 });

  useEffect(() => {
    async function loadCounts() {
      try {
        const res = await fetch('/api/emails?folder=inbox');
        if (res.ok) {
          const data = await res.json();
          if (data.unreadCounts) {
            setUnreadCounts(data.unreadCounts);
          }
        }
      } catch {}
    }
    loadCounts();
    const handleDispatched = () => loadCounts();
    window.addEventListener('email-dispatched', handleDispatched);
    const interval = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      loadCounts();
    }, 6000);
    return () => {
      window.removeEventListener('email-dispatched', handleDispatched);
      clearInterval(interval);
    };
  }, []);

  return (
    <>
      {/* Mobile Drawer Overlay Backdrop */}
      {mobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/75 backdrop-blur-sm z-40 md:hidden transition-opacity duration-200"
          aria-hidden="true"
        />
      )}

      <aside
        className={clsx(
          'fixed top-0 left-0 z-50 h-screen flex flex-col transition-all duration-300 ease-in-out',
          'surface-1 border-r border-default',
          collapsed ? 'md:w-[60px]' : 'md:w-[240px]',
          'w-[280px]',
          mobileOpen ? 'translate-x-0 shadow-2xl visible' : '-translate-x-full invisible md:visible md:translate-x-0'
        )}
      >
        {/* ── Logo & Mobile Close ── */}
        <div className="flex items-center justify-between h-[56px] px-4 border-b border-default">
          <Link
            href={isAdmin ? '/admin/dashboard' : '/user/dashboard'}
            onClick={onCloseMobile}
            className="flex items-center gap-2.5 overflow-hidden"
          >
            <div className="flex-shrink-0 w-7 h-7 flex items-center justify-center">
              <svg viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-7 h-7">
                <path d="M14 2L24 8V20L14 26L4 20V8L14 2Z" stroke="var(--color-accent)" strokeWidth="1.5" fill="none" />
                <path d="M14 6L20 9.5V16.5L14 20L8 16.5V9.5L14 6Z" stroke="var(--color-accent)" strokeWidth="1" fill="var(--color-accent-dim)" />
                <path d="M14 10L17 11.75V15.25L14 17L11 15.25V11.75L14 10Z" fill="var(--color-accent)" />
              </svg>
            </div>
            {(!collapsed || mobileOpen) && (
              <div className="flex flex-col leading-none">
                <span className="text-[13px] font-bold tracking-wider text-[var(--color-text-primary)]">
                  GARUDA
                </span>
                <span className="text-[10px] font-medium tracking-widest text-[var(--color-accent)] uppercase">
                  {isAdmin ? 'ADMIN' : 'SECURE'}
                </span>
              </div>
            )}
          </Link>

          <button
            type="button"
            onClick={onCloseMobile}
            className="md:hidden p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-white hover:bg-[var(--color-surface-2)] transition-colors"
            aria-label="Close navigation"
          >
            <X size={18} />
          </button>
        </div>

        {/* ── Compose Button ── */}
        <div className={clsx('px-2 pt-3', collapsed ? 'px-1.5 md:px-1.5' : 'px-3')}>
          <Link
            href="/compose"
            onClick={onCloseMobile}
            className={clsx(
              'flex items-center justify-center gap-2 rounded-xl font-semibold transition-all duration-200',
              'bg-gradient-to-r from-sky-500 via-indigo-500 to-purple-600 hover:from-sky-400 hover:via-indigo-400 hover:to-purple-500 text-white shadow-lg shadow-indigo-500/25 active:scale-[0.97] border border-white/20',
              collapsed ? 'w-full md:w-9 h-9 md:mx-auto' : 'w-full h-9 px-4 text-[13px]'
            )}
          >
            <Plus size={16} strokeWidth={2.5} />
            {(!collapsed || mobileOpen) && <span>Compose</span>}
          </Link>
        </div>

        {/* ── Navigation ── */}
        <nav className="flex-1 overflow-y-auto py-2 px-2">
          {/* USER SPECIFIC NAVIGATION */}
          {!isAdmin ? (
            <div className="space-y-0.5">
              {!collapsed && (
                <div className="px-2 pt-2 pb-1.5">
                  <span className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-semibold flex items-center gap-1.5">
                    <Shield size={10} />
                    USER WORKSPACE
                  </span>
                </div>
              )}
              {userNav.map((item) => {
                const isActive = pathname === item.href;
                const count = (item as any).countKey ? unreadCounts[(item as any).countKey] : undefined;
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    onClick={onCloseMobile}
                    title={collapsed ? item.name : undefined}
                    className={clsx(
                      'flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13px] font-medium transition-all duration-150',
                      isActive
                        ? clsx(item.activeBg, 'shadow-sm font-semibold')
                        : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent',
                      collapsed && 'md:justify-center md:px-0'
                    )}
                  >
                    <item.icon className={clsx('flex-shrink-0 transition-colors', isActive ? item.color : 'text-[var(--color-text-muted)]')} size={18} strokeWidth={1.8} />
                    {(!collapsed || mobileOpen) && (
                      <>
                        <span className="truncate flex-1">{item.name}</span>
                        {count && count > 0 && (
                          <span className="text-[10px] font-bold tabular-nums bg-sky-500 text-white rounded-full min-w-[18px] h-[18px] flex items-center justify-center px-1 shadow-sm shadow-sky-500/30">
                            {count}
                          </span>
                        )}
                      </>
                    )}
                  </Link>
                );
              })}
            </div>
          ) : (
            /* ADMIN SPECIFIC NAVIGATION */
            <div className="space-y-0.5">
              {/* Admin Privileged Section */}
              {!collapsed && (
                <div className="px-2 pt-2 pb-1.5">
                  <span className="text-[10px] uppercase tracking-widest text-rose-400 font-semibold flex items-center gap-1.5">
                    <ShieldAlert size={10} />
                    ADMINISTRATION (ROOT)
                  </span>
                </div>
              )}
              {adminNav.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    onClick={onCloseMobile}
                    title={collapsed ? item.name : undefined}
                    className={clsx(
                      'flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13px] font-medium transition-all duration-150',
                      isActive
                        ? clsx(item.activeBg, 'shadow-sm font-semibold')
                        : 'text-rose-300/80 hover:text-white hover:bg-rose-500/10 border border-transparent',
                      collapsed && 'md:justify-center md:px-0'
                    )}
                  >
                    <item.icon className={clsx('flex-shrink-0 transition-colors', isActive ? item.color : 'text-rose-400/80')} size={18} strokeWidth={1.8} />
                    {(!collapsed || mobileOpen) && <span className="truncate flex-1">{item.name}</span>}
                  </Link>
                );
              })}

              <div className={clsx('my-3', collapsed ? 'mx-2' : 'mx-3')}>
                <div className="h-px bg-[var(--color-border)]" />
              </div>

              {/* Email Section */}
              {!collapsed && (
                <div className="px-2 pb-1.5">
                  <span className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-semibold flex items-center gap-1.5">
                    <Mail size={10} />
                    EMAIL COMMUNICATIONS
                  </span>
                </div>
              )}
              {emailNav.slice(0, 4).map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    onClick={onCloseMobile}
                    title={collapsed ? item.name : undefined}
                    className={clsx(
                      'flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13px] font-medium transition-all duration-150',
                      isActive
                        ? clsx(item.activeBg, 'shadow-sm font-semibold')
                        : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent',
                      collapsed && 'md:justify-center md:px-0'
                    )}
                  >
                    <item.icon className={clsx('flex-shrink-0 transition-colors', isActive ? item.color : 'text-[var(--color-text-muted)]')} size={18} strokeWidth={1.8} />
                    {(!collapsed || mobileOpen) && <span className="truncate flex-1">{item.name}</span>}
                  </Link>
                );
              })}

              <div className={clsx('my-3', collapsed ? 'mx-2' : 'mx-3')}>
                <div className="h-px bg-[var(--color-border)]" />
              </div>

              {/* Forensic Telemetry Section */}
              {!collapsed && (
                <div className="px-2 pb-1.5">
                  <span className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-semibold flex items-center gap-1.5">
                    <Shield size={10} />
                    FORENSIC TELEMETRY
                  </span>
                </div>
              )}
              {systemNav.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    onClick={onCloseMobile}
                    title={collapsed ? item.name : undefined}
                    className={clsx(
                      'flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13px] font-medium transition-all duration-150',
                      isActive
                        ? clsx(item.activeBg, 'shadow-sm font-semibold')
                        : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent',
                      collapsed && 'md:justify-center md:px-0'
                    )}
                  >
                    <item.icon className={clsx('flex-shrink-0 transition-colors', isActive ? item.color : 'text-[var(--color-text-muted)]')} size={18} strokeWidth={1.8} />
                    {(!collapsed || mobileOpen) && <span className="truncate">{item.name}</span>}
                  </Link>
                );
              })}
            </div>
          )}
        </nav>

      {/* ── System Status ── */}
      {(!collapsed || mobileOpen) && (
        <div className="px-3 py-3 border-t border-default">
          <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] font-semibold mb-2">System Status</div>
          <div className="space-y-1.5">
            <StatusDot label="FastAPI Backend (8000)" status="connected" />
            <StatusDot label="Analysis Engine" status="connected" />
            <StatusDot label="AI Forensics Engine" status="connected" />
            <StatusDot label="Laptop & Mobile Sync" status="connected" />
          </div>
        </div>
      )}

      {/* ── Collapse Toggle (Desktop only) ── */}
      <button
        onClick={onToggle}
        className="hidden md:flex items-center justify-center h-8 border-t border-default text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] transition-colors"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
      </button>
    </aside>
    </>
  );
}

function StatusDot({ label, status }: { label: string; status: 'connected' | 'processing' | 'degraded' | 'offline' }) {
  const color = {
    connected: 'bg-[var(--color-severity-healthy)]',
    processing: 'bg-[var(--color-accent)]',
    degraded: 'bg-[var(--color-severity-high)]',
    offline: 'bg-[var(--color-severity-critical)]',
  }[status];

  return (
    <div className="flex items-center gap-2">
      <div className={clsx('w-1.5 h-1.5 rounded-full', color)} />
      <span className="text-[11px] text-[var(--color-text-muted)]">{label}</span>
    </div>
  );
}
