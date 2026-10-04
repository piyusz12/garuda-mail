'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState, useEffect } from 'react';
import {
  Inbox,
  Send,
  FileEdit,
  Star,
  Archive,
  Trash2,
  LayoutDashboard,
  Upload,
  Network,
  AlertTriangle,
  Shield,
  Award,
  Brain,
  Search as SearchIcon,
  FileText,
  Settings,
  Layers,
  ChevronLeft,
  ChevronRight,
  Plus,
  Mail,
  Activity,

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

  const [unreadCounts, setUnreadCounts] = useState<{
    inbox?: number;
    drafts?: number;
  }>({
    inbox: 2,
    drafts: 0,
  });

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
        'fixed left-0 top-0 z-40 flex h-screen flex-col',
        'border-r border-[var(--color-border-subtle)]',
        'bg-[rgba(10,13,17,0.96)] backdrop-blur-xl',
        'transition-all duration-300 ease-in-out',
        collapsed ? 'w-[68px]' : 'w-[248px]'
      )}
    >
      {/* ─────────────────────────────────────────────────────
          BRAND
      ───────────────────────────────────────────────────── */}

      <div
        className={clsx(
          'relative flex h-[64px] shrink-0 items-center',
          'border-b border-[var(--color-border-subtle)]',
          collapsed ? 'justify-center px-3' : 'px-4'
        )}
      >
        {/* subtle top accent */}
        <div className="absolute left-0 right-0 top-0 h-px bg-gradient-to-r from-transparent via-[rgba(56,189,248,0.35)] to-transparent" />

        <Link
          href="/inbox"
          className="group flex items-center gap-3 overflow-hidden"
        >
          {/* Logo */}
          <div
            className={clsx(
              'relative flex h-9 w-9 shrink-0 items-center justify-center',
              'rounded-xl border border-[rgba(56,189,248,0.18)]',
              'bg-[rgba(56,189,248,0.06)]',
              'transition-all duration-200',
              'group-hover:border-[rgba(56,189,248,0.38)]',
              'group-hover:bg-[rgba(56,189,248,0.10)]'
            )}
          >
            <svg
              viewBox="0 0 28 28"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              className="h-6 w-6"
            >
              <path
                d="M14 2L24 8V20L14 26L4 20V8L14 2Z"
                stroke="var(--color-accent)"
                strokeWidth="1.35"
              />

              <path
                d="M14 6L20 9.5V16.5L14 20L8 16.5V9.5L14 6Z"
                stroke="var(--color-accent)"
                strokeWidth="1"
                fill="var(--color-accent-dim)"
              />

              <path
                d="M14 10L17 11.75V15.25L14 17L11 15.25V11.75L14 10Z"
                fill="var(--color-accent)"
              />
            </svg>

            <span className="absolute inset-0 rounded-xl shadow-[0_0_22px_rgba(56,189,248,0.10)]" />
          </div>

          {!collapsed && (
            <div className="flex min-w-0 flex-col justify-center">
              <span className="text-[13px] font-bold leading-none tracking-[0.18em] text-[var(--color-text-primary)]">
                GARUDA
              </span>

              <div className="mt-1 flex items-center gap-1.5">
                <span className="text-[9px] font-semibold uppercase tracking-[0.28em] text-[var(--color-accent)]">
                  MAIL
                </span>

                <span className="h-1 w-1 rounded-full bg-[var(--color-accent)] opacity-60" />

                <span className="text-[8px] uppercase tracking-wider text-[var(--color-text-dim)]">
                  SOC
                </span>
              </div>
            </div>
          )}
        </Link>
      </div>

      {/* ─────────────────────────────────────────────────────
          COMPOSE
      ───────────────────────────────────────────────────── */}

      <div className={clsx('shrink-0', collapsed ? 'px-2 py-3' : 'px-3 py-4')}>
        <Link
          href="/compose"
          title={collapsed ? 'Compose' : undefined}
          className={clsx(
            'group relative flex items-center justify-center gap-2',
            'overflow-hidden rounded-xl',
            'border border-[rgba(56,189,248,0.22)]',
            'bg-[linear-gradient(135deg,rgba(56,189,248,0.14),rgba(56,189,248,0.06))]',
            'text-[var(--color-accent-bright)]',
            'shadow-[0_4px_18px_rgba(0,0,0,0.15)]',
            'transition-all duration-200',
            'hover:border-[rgba(56,189,248,0.40)]',
            'hover:bg-[rgba(56,189,248,0.13)]',
            'hover:shadow-[0_6px_24px_rgba(56,189,248,0.08)]',
            'active:scale-[0.98]',
            collapsed ? 'mx-auto h-10 w-10' : 'h-10 w-full px-4'
          )}
        >
          <Plus
            size={17}
            strokeWidth={2.4}
            className="transition-transform duration-200 group-hover:rotate-90"
          />

          {!collapsed && (
            <>
              <span className="text-[12px] font-semibold tracking-wide">
                Compose
              </span>

              <span className="ml-auto rounded-md border border-white/[0.06] bg-black/20 px-1.5 py-0.5 text-[8px] font-medium text-[var(--color-text-dim)]">
                C
              </span>
            </>
          )}
        </Link>
      </div>

      {/* ─────────────────────────────────────────────────────
          NAVIGATION
      ───────────────────────────────────────────────────── */}

      <nav className="min-h-0 flex-1 overflow-y-auto px-2 pb-3">
        {/* EMAIL */}

        {!collapsed && (
          <SectionLabel icon={<Mail size={11} />} label="Mail" />
        )}

        <div className="space-y-0.5">
          {emailNav.map((item) => {
            const isActive = pathname === item.href;
            const count = item.countKey
              ? unreadCounts[item.countKey]
              : undefined;

            return (
              <NavItem
                key={item.name}
                item={item}
                isActive={isActive}
                collapsed={collapsed}
                count={count}
              />
            );
          })}
        </div>

        {/* DIVIDER */}

        <div className={clsx('my-4', collapsed ? 'px-2' : 'px-3')}>
          <div className="h-px bg-gradient-to-r from-transparent via-[var(--color-border)] to-transparent" />
        </div>

        {/* SECURITY */}

        {!collapsed && (
          <SectionLabel icon={<Shield size={11} />} label="Security Intelligence" />
        )}

        <div className="space-y-0.5">
          {securityNav.map((item) => {
            const isActive =
              pathname === item.href ||
              pathname?.startsWith(item.href + '/');

            return (
              <NavItem
                key={item.name}
                item={item}
                isActive={isActive}
                collapsed={collapsed}
              />
            );
          })}
        </div>
      </nav>

      {/* ─────────────────────────────────────────────────────
          SYSTEM STATUS
      ───────────────────────────────────────────────────── */}

      {!collapsed && (
        <div className="shrink-0 border-t border-[var(--color-border-subtle)] px-3 py-3">
          <div className="mb-2.5 flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <Activity
                size={11}
                className="text-[var(--color-text-muted)]"
              />

              <span className="text-[9px] font-semibold uppercase tracking-[0.16em] text-[var(--color-text-dim)]">
                System Status
              </span>
            </div>

            <span className="flex items-center gap-1 text-[8px] uppercase tracking-wider text-[var(--color-severity-healthy)]">
              <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-severity-healthy)] shadow-[0_0_8px_rgba(52,211,153,0.5)]" />
              Operational
            </span>
          </div>

          <div className="rounded-xl border border-[var(--color-border-subtle)] bg-[rgba(255,255,255,0.015)] p-2.5">
            <div className="space-y-2">
              <StatusRow label="Backend" status="connected" />
              <StatusRow label="Analysis Engine" status="connected" />
              <StatusRow label="AI Engine" status="connected" />
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────
          COLLAPSE
      ───────────────────────────────────────────────────── */}

      <button
        onClick={onToggle}
        className={clsx(
          'group flex h-9 shrink-0 items-center justify-center',
          'border-t border-[var(--color-border-subtle)]',
          'text-[var(--color-text-muted)]',
          'transition-all duration-200',
          'hover:bg-[rgba(255,255,255,0.025)]',
          'hover:text-[var(--color-text-primary)]'
        )}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? (
          <ChevronRight
            size={15}
            className="transition-transform duration-200 group-hover:translate-x-0.5"
          />
        ) : (
          <ChevronLeft
            size={15}
            className="transition-transform duration-200 group-hover:-translate-x-0.5"
          />
        )}
      </button>
    </aside>
  );
}

/* ─────────────────────────────────────────────────────────────
   NAV ITEM
   ───────────────────────────────────────────────────────────── */

function NavItem({
  item,
  isActive,
  collapsed,
  count,
}: {
  item: any;
  isActive: boolean;
  collapsed: boolean;
  count?: number;
}) {
  return (
    <Link
      href={item.href}
      title={collapsed ? item.name : undefined}
      className={clsx(
        'group relative flex items-center gap-2.5',
        'rounded-lg border px-2.5 py-[8px]',
        'text-[12px] font-medium',
        'transition-all duration-150',

        isActive
          ? [
              'border-[rgba(56,189,248,0.13)]',
              'bg-[rgba(56,189,248,0.075)]',
              'text-[var(--color-text-primary)]',
            ]
          : [
              'border-transparent',
              'text-[var(--color-text-secondary)]',
              'hover:border-[rgba(255,255,255,0.035)]',
              'hover:bg-[rgba(255,255,255,0.025)]',
              'hover:text-[var(--color-text-primary)]',
            ],

        collapsed && 'justify-center px-0'
      )}
    >
      {/* Active indicator */}

      {isActive && (
        <span className="absolute bottom-1.5 left-0 top-1.5 w-[2px] rounded-full bg-[var(--color-accent)] shadow-[0_0_10px_rgba(56,189,248,0.55)]" />
      )}

      <item.icon
        size={17}
        strokeWidth={isActive ? 2 : 1.7}
        className={clsx(
          'shrink-0 transition-colors duration-150',
          isActive
            ? 'text-[var(--color-accent)]'
            : 'text-[var(--color-text-muted)] group-hover:text-[var(--color-text-secondary)]'
        )}
      />

      {!collapsed && (
        <>
          <span className="min-w-0 flex-1 truncate">{item.name}</span>

          {count !== undefined && count > 0 && (
            <span
              className={clsx(
                'flex h-[18px] min-w-[18px] items-center justify-center',
                'rounded-full px-1',
                'bg-[rgba(56,189,248,0.13)]',
                'text-[9px] font-bold tabular-nums',
                'text-[var(--color-accent)]',
                'border border-[rgba(56,189,248,0.12)]'
              )}
            >
              {count}
            </span>
          )}
        </>
      )}
    </Link>
  );
}

/* ─────────────────────────────────────────────────────────────
   SECTION LABEL
   ───────────────────────────────────────────────────────────── */

function SectionLabel({
  icon,
  label,
}: {
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <div className="flex items-center gap-2 px-2.5 pb-2 pt-1">
      <span className="text-[var(--color-text-dim)]">{icon}</span>

      <span className="text-[9px] font-bold uppercase tracking-[0.18em] text-[var(--color-text-dim)]">
        {label}
      </span>

      <div className="ml-auto h-px flex-1 bg-[var(--color-border-subtle)]" />
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────
   STATUS ROW
   ───────────────────────────────────────────────────────────── */

function StatusRow({
  label,
  status,
}: {
  label: string;
  status: 'connected' | 'processing' | 'degraded' | 'offline';
}) {
  const config = {
    connected: {
      color: 'bg-[var(--color-severity-healthy)]',
      glow: 'shadow-[0_0_7px_rgba(52,211,153,0.45)]',
      text: 'Online',
    },
    processing: {
      color: 'bg-[var(--color-accent)]',
      glow: 'shadow-[0_0_7px_rgba(56,189,248,0.45)]',
      text: 'Active',
    },
    degraded: {
      color: 'bg-[var(--color-severity-high)]',
      glow: 'shadow-[0_0_7px_rgba(246,168,75,0.45)]',
      text: 'Degraded',
    },
    offline: {
      color: 'bg-[var(--color-severity-critical)]',
      glow: 'shadow-[0_0_7px_rgba(255,92,104,0.45)]',
      text: 'Offline',
    },
  }[status];

  return (
    <div className="flex items-center justify-between">
      <div className="flex min-w-0 items-center gap-2">
        <span
          className={clsx(
            'h-1.5 w-1.5 shrink-0 rounded-full',
            config.color,
            config.glow
          )}
        />

        <span className="truncate text-[10px] text-[var(--color-text-muted)]">
          {label}
        </span>
      </div>

      <span className="text-[8px] font-medium uppercase tracking-wider text-[var(--color-text-dim)]">
        {config.text}
      </span>
    </div>
  );
}