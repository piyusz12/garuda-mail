'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState, useEffect } from 'react';
import {
  Inbox, Send, FileEdit, Star, Archive, Trash2,
  LayoutDashboard, Upload, Network, AlertTriangle, Shield,
  Award, Brain, Search as SearchIcon, FileText, Settings, Layers,
  ChevronLeft, ChevronRight, Plus, Mail,
} from 'lucide-react';
import clsx from 'clsx';

const emailNav = [
  { name: 'Inbox', href: '/inbox', icon: Inbox, countKey: 'inbox' as const },
  { name: 'Sent', href: '/sent', icon: Send },
  { name: 'Drafts', href: '/drafts', icon: FileEdit, countKey: 'drafts' as const },
  { name: 'Starred', href: '/starred', icon: Star },
  { name: 'Archive', href: '/archive', icon: Archive },
  { name: 'Trash', href: '/trash', icon: Trash2 },
];

const securityNav = [
  { name: 'Overview', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Analysis', href: '/analysis', icon: Upload },
  { name: 'Sessions', href: '/sessions', icon: Network },
  { name: 'Findings', href: '/findings', icon: AlertTriangle },
  { name: 'Crypto Posture', href: '/crypto', icon: Shield },
  { name: 'Certificates', href: '/certificates', icon: Award },
  { name: 'AI Anomalies', href: '/anomalies', icon: Brain },
  { name: 'Investigations', href: '/investigations', icon: SearchIcon },
  { name: 'CBOM', href: '/cbom', icon: Layers },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Settings', href: '/settings', icon: Settings },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const pathname = usePathname();
  const [unreadCounts, setUnreadCounts] = useState<{ inbox?: number; drafts?: number }>({ inbox: 2, drafts: 0 });

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
    const interval = setInterval(loadCounts, 8000);
    return () => clearInterval(interval);
  }, []);

  return (
    <aside
      className={clsx(
        'fixed top-0 left-0 z-40 h-screen flex flex-col transition-all duration-300 ease-in-out',
        'surface-1 border-r border-default',
        collapsed ? 'w-[60px]' : 'w-[240px]'
      )}
    >
      {/* ── Logo ── */}
      <div className="flex items-center h-[56px] px-4 border-b border-default">
        <Link href="/inbox" className="flex items-center gap-2.5 overflow-hidden">
          <div className="flex-shrink-0 w-7 h-7 flex items-center justify-center">
            <svg viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-7 h-7">
              <path d="M14 2L24 8V20L14 26L4 20V8L14 2Z" stroke="var(--color-accent)" strokeWidth="1.5" fill="none" />
              <path d="M14 6L20 9.5V16.5L14 20L8 16.5V9.5L14 6Z" stroke="var(--color-accent)" strokeWidth="1" fill="var(--color-accent-dim)" />
              <path d="M14 10L17 11.75V15.25L14 17L11 15.25V11.75L14 10Z" fill="var(--color-accent)" />
            </svg>
          </div>
          {!collapsed && (
            <div className="flex flex-col leading-none">
              <span className="text-[13px] font-bold tracking-wider text-[var(--color-text-primary)]">
                GARUDA
              </span>
              <span className="text-[10px] font-medium tracking-widest text-[var(--color-accent)] uppercase">
                MAIL
              </span>
            </div>
          )}
        </Link>
      </div>

      {/* ── Compose Button ── */}
      <div className={clsx('px-2 pt-3', collapsed ? 'px-1.5' : 'px-3')}>
        <Link
          href="/compose"
          className={clsx(
            'flex items-center justify-center gap-2 rounded-lg font-medium transition-all duration-200',
            'bg-[var(--color-accent)] text-[#0B0D10] hover:bg-[#5ccbfc] active:scale-[0.97]',
            collapsed ? 'w-9 h-9 mx-auto' : 'w-full h-9 px-4 text-[13px]'
          )}
        >
          <Plus size={16} strokeWidth={2.5} />
          {!collapsed && <span>Compose</span>}
        </Link>
      </div>

      {/* ── Navigation ── */}
      <nav className="flex-1 overflow-y-auto py-2 px-2">
        {/* Email Section */}
        {!collapsed && (
          <div className="px-2 pt-2 pb-1.5">
            <span className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-semibold flex items-center gap-1.5">
              <Mail size={10} />
              EMAIL
            </span>
          </div>
        )}
        <div className="space-y-0.5">
          {emailNav.map((item) => {
            const isActive = pathname === item.href;
            const count = item.countKey ? (unreadCounts as any)[item.countKey] : undefined;
            return (
              <Link
                key={item.name}
                href={item.href}
                title={collapsed ? item.name : undefined}
                className={clsx(
                  'flex items-center gap-2.5 px-2.5 py-2 rounded-md text-[13px] font-medium transition-all duration-150',
                  isActive
                    ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[rgba(56,189,248,0.12)]'
                    : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent',
                  collapsed && 'justify-center px-0'
                )}
              >
                <item.icon className={clsx('flex-shrink-0', isActive ? 'text-[var(--color-accent)]' : 'text-[var(--color-text-muted)]')} size={18} strokeWidth={1.8} />
                {!collapsed && (
                  <>
                    <span className="truncate flex-1">{item.name}</span>
                    {count && count > 0 && (
                      <span className="text-[10px] font-bold tabular-nums bg-[var(--color-accent)] text-[#0B0D10] rounded-full min-w-[18px] h-[18px] flex items-center justify-center px-1">
                        {count}
                      </span>
                    )}
                  </>
                )}
              </Link>
            );
          })}
        </div>

        {/* Divider */}
        <div className={clsx('my-3', collapsed ? 'mx-2' : 'mx-3')}>
          <div className="h-px bg-[var(--color-border)]" />
        </div>

        {/* Security Section */}
        {!collapsed && (
          <div className="px-2 pb-1.5">
            <span className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-semibold flex items-center gap-1.5">
              <Shield size={10} />
              SECURITY
            </span>
          </div>
        )}
        <div className="space-y-0.5">
          {securityNav.map((item) => {
            const isActive = pathname === item.href || pathname?.startsWith(item.href + '/');
            return (
              <Link
                key={item.name}
                href={item.href}
                title={collapsed ? item.name : undefined}
                className={clsx(
                  'flex items-center gap-2.5 px-2.5 py-2 rounded-md text-[13px] font-medium transition-all duration-150',
                  isActive
                    ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[rgba(56,189,248,0.12)]'
                    : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent',
                  collapsed && 'justify-center px-0'
                )}
              >
                <item.icon className={clsx('flex-shrink-0', isActive ? 'text-[var(--color-accent)]' : 'text-[var(--color-text-muted)]')} size={18} strokeWidth={1.8} />
                {!collapsed && <span className="truncate">{item.name}</span>}
              </Link>
            );
          })}
        </div>
      </nav>

      {/* ── System Status ── */}
      {!collapsed && (
        <div className="px-3 py-3 border-t border-default">
          <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] font-semibold mb-2">System Status</div>
          <div className="space-y-1.5">
            <StatusDot label="Backend" status="connected" />
            <StatusDot label="Analysis Engine" status="connected" />
            <StatusDot label="AI Engine" status="connected" />
          </div>
        </div>
      )}

      {/* ── Collapse Toggle ── */}
      <button
        onClick={onToggle}
        className="flex items-center justify-center h-8 border-t border-default text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] transition-colors"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
      </button>
    </aside>
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
