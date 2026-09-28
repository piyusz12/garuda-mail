'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import {
  LayoutDashboard, Upload, Network, AlertTriangle, Shield,
  Award, Brain, Search as SearchIcon, FileText, Settings, Layers,
  ChevronLeft, ChevronRight, Activity,
} from 'lucide-react';
import clsx from 'clsx';

const navigation = [
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
        <Link href="/dashboard" className="flex items-center gap-2.5 overflow-hidden">
          {/* Garuda Mark — geometric minimal symbol */}
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

      {/* ── Navigation ── */}
      <nav className="flex-1 overflow-y-auto py-3 px-2">
        <div className="space-y-0.5">
          {navigation.map((item) => {
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
