'use client';

import { useState } from 'react';
import { Search, Bell, Sun, Moon, Wifi, WifiOff, User, Activity } from 'lucide-react';
import clsx from 'clsx';

interface TopBarProps {
  title: string;
  description?: string;
}

export default function TopBar({ title, description }: TopBarProps) {
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <header className="sticky top-0 z-30 h-[56px] flex items-center justify-between px-6 surface-1 border-b border-default backdrop-blur-md">
      {/* ── Left: Page Context ── */}
      <div className="flex items-center gap-3 min-w-0">
        <div className="min-w-0">
          <h1 className="text-[15px] font-semibold text-[var(--color-text-primary)] truncate">{title}</h1>
          {description && (
            <p className="text-[11px] text-[var(--color-text-muted)] truncate">{description}</p>
          )}
        </div>
      </div>

      {/* ── Right: Actions ── */}
      <div className="flex items-center gap-1">
        {/* Search */}
        <div className="relative">
          {searchOpen ? (
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search sessions, findings, hosts..."
                  autoFocus
                  onBlur={() => { if (!searchQuery) setSearchOpen(false); }}
                  className="w-[280px] h-8 pl-8 pr-3 text-[12px] rounded-md bg-[var(--color-surface-2)] border border-default text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
                />
              </div>
              <kbd className="hidden md:inline-flex items-center px-1.5 h-5 text-[10px] font-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] border border-default rounded">
                ESC
              </kbd>
            </div>
          ) : (
            <button
              onClick={() => setSearchOpen(true)}
              className="flex items-center gap-2 h-8 px-3 text-[12px] text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] bg-[var(--color-surface-2)] border border-default rounded-md hover:border-[var(--color-border-active)] transition-colors"
            >
              <Search size={14} />
              <span className="hidden md:inline">Search</span>
              <kbd className="hidden md:inline-flex items-center px-1.5 h-4 text-[10px] font-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] rounded">
                ⌘K
              </kbd>
            </button>
          )}
        </div>

        <div className="w-px h-5 bg-[var(--color-border)] mx-2" />

        {/* Analysis Status */}
        <TopBarButton icon={Activity} label="Analysis Ready" variant="status" />

        {/* API Status */}
        <TopBarButton icon={Wifi} label="API Connected" variant="healthy" />

        {/* Notifications */}
        <TopBarButton icon={Bell} label="3 notifications" badge={3} />

        {/* User */}
        <button className="flex items-center justify-center w-8 h-8 rounded-md text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] transition-colors">
          <div className="w-6 h-6 rounded-full bg-[var(--color-accent-dim)] border border-[var(--color-accent-muted)] flex items-center justify-center">
            <span className="text-[10px] font-bold text-[var(--color-accent)]">GA</span>
          </div>
        </button>
      </div>
    </header>
  );
}

function TopBarButton({
  icon: Icon,
  label,
  variant,
  badge,
}: {
  icon: React.ElementType;
  label: string;
  variant?: 'status' | 'healthy';
  badge?: number;
}) {
  return (
    <button
      title={label}
      className="relative flex items-center justify-center w-8 h-8 rounded-md text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] transition-colors"
    >
      <Icon size={16} className={clsx(
        variant === 'healthy' && 'text-[var(--color-severity-healthy)]',
        variant === 'status' && 'text-[var(--color-accent)]',
      )} />
      {badge && badge > 0 && (
        <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center w-4 h-4 text-[9px] font-bold text-white bg-[var(--color-severity-critical)] rounded-full">
          {badge}
        </span>
      )}
    </button>
  );
}
