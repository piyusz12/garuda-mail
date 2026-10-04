'use client';

import { useState, useRef, useEffect } from 'react';
import { useSession, signOut } from 'next-auth/react';
import {
  Search,
  Bell,
  Wifi,
  Activity,
  Check,
  Clock,
  ExternalLink,
  Settings as SettingsIcon,
  LogOut,
  Laptop,
  ShieldCheck,
  ChevronDown,
} from 'lucide-react';
import clsx from 'clsx';
import Link from 'next/link';

interface TopBarProps {
  title: string;
  description?: string;
}

export default function TopBar({ title, description }: TopBarProps) {
  const { data: session } = useSession();

  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeDropdown, setActiveDropdown] = useState<
    'notifications' | 'api' | 'user' | null
  >(null);

  const [notifications, setNotifications] = useState([
    {
      id: 1,
      title: 'STARTTLS Downgrade Detected',
      desc: 'Plaintext IMAP session without TLS on port 143',
      time: '12m ago',
      unread: true,
      sev: 'critical',
    },
    {
      id: 2,
      title: 'Certificate Expiry Warning',
      desc: 'mail.example.com certificate expires in 18 days',
      time: '1h ago',
      unread: true,
      sev: 'high',
    },
    {
      id: 3,
      title: 'Rare JA4 Fingerprint Observed',
      desc: 'New rare JA4 signature seen on SMTP-0192',
      time: '3h ago',
      unread: false,
      sev: 'medium',
    },
  ]);

  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setActiveDropdown(null);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  useEffect(() => {
    function handleKeyboard(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setSearchOpen(false);
        setActiveDropdown(null);
      }

      if (
        (event.ctrlKey || event.metaKey) &&
        event.key.toLowerCase() === 'k'
      ) {
        event.preventDefault();
        setSearchOpen(true);
      }
    }

    document.addEventListener('keydown', handleKeyboard);

    return () => {
      document.removeEventListener('keydown', handleKeyboard);
    };
  }, []);

  const unreadCount = notifications.filter((n) => n.unread).length;

  const userName = session?.user?.name || 'Garuda Analyst';
  const userEmail =
    session?.user?.email || 'analyst@enterprise.local';

  const userInitials = userName
    .split(' ')
    .map((w) => w[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();

  const toggleDropdown = (
    dropdown: 'notifications' | 'api' | 'user'
  ) => {
    setActiveDropdown(
      activeDropdown === dropdown ? null : dropdown
    );
  };

  return (
    <header className="relative sticky top-0 z-30 h-[64px] flex items-center justify-between gap-4 px-5 md:px-6 bg-[rgba(8,10,13,0.88)] backdrop-blur-xl border-b border-[var(--color-border-subtle)]">

      {/* subtle top accent */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[rgba(56,189,248,0.35)] to-transparent pointer-events-none" />

      {/* ───────────────── LEFT ───────────────── */}

      <div className="flex items-center gap-3 min-w-0">

        {/* Security indicator */}
        <div className="hidden sm:flex items-center justify-center w-8 h-8 rounded-lg bg-[var(--color-accent-glow)] border border-[rgba(56,189,248,0.14)]">
          <ShieldCheck
            size={15}
            className="text-[var(--color-accent)]"
          />
        </div>

        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-[14px] md:text-[15px] font-semibold tracking-[-0.01em] text-[var(--color-text-primary)] truncate">
              {title}
            </h1>

            <span className="hidden sm:inline-flex items-center gap-1 text-[9px] uppercase tracking-[0.12em] font-medium text-[var(--color-severity-healthy)]">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-severity-healthy)] shadow-[0_0_7px_rgba(52,211,153,0.7)]" />
              Live
            </span>
          </div>

          {description && (
            <p className="text-[10px] md:text-[11px] text-[var(--color-text-muted)] truncate mt-0.5">
              {description}
            </p>
          )}
        </div>
      </div>

      {/* ───────────────── RIGHT ───────────────── */}

      <div
        className="relative flex items-center gap-1"
        ref={dropdownRef}
      >

        {/* Search */}
        <div className="relative">

          {searchOpen ? (
            <div className="flex items-center gap-2 animate-in fade-in slide-in-from-right-2 duration-150">

              <div className="relative">
                <Search
                  size={14}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]"
                />

                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search emails..."
                  autoFocus
                  onKeyDown={(e) => {
                    if (
                      e.key === 'Enter' &&
                      searchQuery.trim()
                    ) {
                      window.location.href = `/inbox?search=${encodeURIComponent(
                        searchQuery.trim()
                      )}`;
                    }
                  }}
                  onBlur={() => {
                    if (!searchQuery) setSearchOpen(false);
                  }}
                  className="w-[220px] md:w-[280px] h-9 pl-9 pr-3 text-[11px] rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-active)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:ring-1 focus:ring-[rgba(56,189,248,0.25)] transition-all"
                />
              </div>

              <kbd className="hidden md:inline-flex items-center px-1.5 h-5 text-[9px] font-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] rounded">
                ESC
              </kbd>

            </div>
          ) : (
            <button
              onClick={() => setSearchOpen(true)}
              className="group flex items-center gap-2 h-9 px-3 text-[11px] text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] bg-[var(--color-surface-1)] border border-[var(--color-border-subtle)] hover:border-[var(--color-border-active)] rounded-lg transition-all"
            >
              <Search
                size={14}
                className="group-hover:text-[var(--color-accent)] transition-colors"
              />

              <span className="hidden md:inline">
                Search emails
              </span>

              <kbd className="hidden lg:inline-flex items-center px-1.5 h-5 text-[9px] font-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] rounded">
                ⌘K
              </kbd>
            </button>
          )}
        </div>

        {/* Divider */}
        <div className="w-px h-6 bg-[var(--color-border-subtle)] mx-1.5" />

        {/* Network */}
        <div>
          <button
            title="Multi-PC Connection Diagnostics"
            onClick={() => toggleDropdown('api')}
            className={clsx(
              'relative flex items-center justify-center w-9 h-9 rounded-lg transition-all',
              activeDropdown === 'api'
                ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] border border-[var(--color-border-active)]'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)]'
            )}
          >
            <Laptop
              size={15}
              className={
                activeDropdown === 'api'
                  ? 'text-[var(--color-accent)]'
                  : ''
              }
            />

            <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-[var(--color-severity-healthy)] shadow-[0_0_5px_rgba(52,211,153,0.6)]" />
          </button>
        </div>

        {/* Notifications */}
        <div>
          <button
            title="Security Notifications"
            onClick={() => toggleDropdown('notifications')}
            className={clsx(
              'relative flex items-center justify-center w-9 h-9 rounded-lg transition-all',
              activeDropdown === 'notifications'
                ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] border border-[var(--color-border-active)]'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)]'
            )}
          >
            <Bell size={15} />

            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 flex items-center justify-center min-w-[15px] h-[15px] px-1 text-[8px] font-bold text-white bg-[var(--color-severity-critical)] rounded-full shadow-[0_0_7px_rgba(255,92,104,0.35)]">
                {unreadCount}
              </span>
            )}
          </button>
        </div>

        {/* User */}
        <div className="relative ml-1">

          <button
            title={`Logged in as ${userName}`}
            onClick={() => toggleDropdown('user')}
            className={clsx(
              'flex items-center gap-2 h-9 pl-1 pr-2 rounded-lg transition-all',
              activeDropdown === 'user'
                ? 'bg-[var(--color-surface-3)] border border-[var(--color-border-active)]'
                : 'hover:bg-[var(--color-surface-2)]'
            )}
          >
            <div className="w-7 h-7 rounded-md bg-[var(--color-accent-dim)] border border-[rgba(56,189,248,0.25)] flex items-center justify-center">
              <span className="text-[9px] font-bold text-[var(--color-accent)]">
                {userInitials}
              </span>
            </div>

            <div className="hidden lg:block text-left max-w-[100px]">
              <div className="text-[10px] font-medium text-[var(--color-text-primary)] truncate">
                {userName}
              </div>
              <div className="text-[8px] text-[var(--color-text-dim)] uppercase tracking-wider">
                Analyst
              </div>
            </div>

            <ChevronDown
              size={12}
              className="hidden lg:block text-[var(--color-text-dim)]"
            />
          </button>
        </div>

        {/* ───────────────── NOTIFICATIONS DROPDOWN ───────────────── */}

        {activeDropdown === 'notifications' && (
          <div className="absolute right-[52px] top-[50px] w-[340px] max-w-[calc(100vw-24px)] bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-150">

            <div className="px-4 py-3 border-b border-[var(--color-border)] bg-[var(--color-surface-2)] flex items-center justify-between">

              <div className="flex items-center gap-2 text-[11px] font-semibold text-[var(--color-text-primary)]">
                <Bell
                  size={13}
                  className="text-[var(--color-accent)]"
                />
                Security Alerts

                <span className="text-[9px] text-[var(--color-text-dim)] font-normal">
                  {notifications.length}
                </span>
              </div>

              {unreadCount > 0 && (
                <button
                  onClick={() =>
                    setNotifications(
                      notifications.map((n) => ({
                        ...n,
                        unread: false,
                      }))
                    )
                  }
                  className="text-[9px] text-[var(--color-accent)] hover:text-[var(--color-accent-bright)] transition-colors"
                >
                  Mark all read
                </button>
              )}
            </div>

            <div className="divide-y divide-[var(--color-border-subtle)] max-h-80 overflow-y-auto">

              {notifications.map((n) => (
                <div
                  key={n.id}
                  className={clsx(
                    'relative p-3.5 hover:bg-[var(--color-surface-2)] transition-colors',
                    n.unread &&
                      'bg-[rgba(56,189,248,0.025)]'
                  )}
                >
                  {n.unread && (
                    <span className="absolute left-0 top-0 bottom-0 w-[2px] bg-[var(--color-accent)]" />
                  )}

                  <div className="flex items-start justify-between gap-3">

                    <span
                      className={clsx(
                        'text-[11px] font-semibold leading-tight',
                        n.sev === 'critical'
                          ? 'text-[var(--color-severity-critical)]'
                          : n.sev === 'high'
                            ? 'text-[var(--color-severity-high)]'
                            : 'text-[var(--color-text-primary)]'
                      )}
                    >
                      {n.title}
                    </span>

                    <span className="text-[9px] text-[var(--color-text-dim)] flex items-center gap-1 whitespace-nowrap">
                      <Clock size={10} />
                      {n.time}
                    </span>
                  </div>

                  <p className="text-[10px] leading-relaxed text-[var(--color-text-muted)] mt-1.5">
                    {n.desc}
                  </p>
                </div>
              ))}

            </div>

            <div className="p-2.5 border-t border-[var(--color-border)] bg-[var(--color-surface-2)] text-center">

              <Link
                href="/findings"
                onClick={() => setActiveDropdown(null)}
                className="text-[10px] text-[var(--color-accent)] hover:text-[var(--color-accent-bright)] inline-flex items-center gap-1 transition-colors"
              >
                View all security findings
                <ExternalLink size={10} />
              </Link>

            </div>
          </div>
        )}

        {/* ───────────────── NETWORK DROPDOWN ───────────────── */}

        {activeDropdown === 'api' && (
          <div className="absolute right-[90px] top-[50px] w-[340px] max-w-[calc(100vw-24px)] bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl p-4 space-y-3 z-50 animate-in fade-in slide-in-from-top-2 duration-150">

            <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">

              <span className="text-[11px] font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                <Wifi
                  size={13}
                  className="text-[var(--color-accent)]"
                />
                Multi-PC Access
              </span>

              <span className="inline-flex items-center gap-1 text-[9px] text-[var(--color-severity-healthy)] font-bold uppercase tracking-wider">
                <Check size={11} />
                Operational
              </span>

            </div>

            <div className="space-y-2.5 text-[10px]">

              <div className="space-y-1 pb-2 border-b border-[var(--color-border-subtle)]">
                <span className="text-[var(--color-text-dim)]">
                  This PC Access
                </span>
                <div className="font-mono text-[var(--color-accent)] break-all">
                  http://localhost:3000
                </div>
              </div>

              <div className="space-y-1 pb-2 border-b border-[var(--color-border-subtle)]">
                <span className="text-[var(--color-text-dim)]">
                  2nd PC Network URL
                </span>
                <div className="font-mono text-[var(--color-severity-healthy)] break-all">
                  http://192.168.1.3:3000
                </div>
              </div>

              <div className="flex items-center justify-between gap-3 pb-2 border-b border-[var(--color-border-subtle)]">
                <span className="text-[var(--color-text-muted)]">
                  Database
                </span>
                <span className="font-mono text-[var(--color-text-primary)] text-right">
                  SQLite / synced
                </span>
              </div>

              <div className="flex items-center justify-between gap-3">
                <span className="text-[var(--color-text-muted)]">
                  Session Auth
                </span>
                <span className="font-mono text-[var(--color-severity-healthy)]">
                  NextAuth Active
                </span>
              </div>

            </div>

            <div className="flex items-start gap-2 pt-2 border-t border-[var(--color-border-subtle)]">
              <Activity
                size={11}
                className="mt-0.5 text-[var(--color-text-dim)] shrink-0"
              />

              <p className="text-[9px] leading-relaxed text-[var(--color-text-dim)]">
                Open the network URL on another computer connected to the same Wi-Fi to test cross-device mail.
              </p>
            </div>

          </div>
        )}

        {/* ───────────────── USER DROPDOWN ───────────────── */}

        {activeDropdown === 'user' && (
          <div className="absolute right-0 top-[50px] w-[270px] max-w-[calc(100vw-24px)] bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-150">

            <div className="p-4 bg-[var(--color-surface-2)] border-b border-[var(--color-border)]">

              <div className="flex items-center gap-3">

                <div className="w-9 h-9 rounded-lg bg-[var(--color-accent-dim)] border border-[rgba(56,189,248,0.25)] flex items-center justify-center">
                  <span className="text-[10px] font-bold text-[var(--color-accent)]">
                    {userInitials}
                  </span>
                </div>

                <div className="min-w-0">
                  <div className="text-[11px] font-semibold text-[var(--color-text-primary)] truncate">
                    {userName}
                  </div>

                  <div className="text-[9px] text-[var(--color-text-dim)] truncate mt-0.5">
                    {userEmail}
                  </div>
                </div>

              </div>

            </div>

            <div className="p-3 space-y-2">

              <div className="flex items-center justify-between px-2 py-1.5 text-[10px]">
                <span className="text-[var(--color-text-muted)]">
                  Domain
                </span>

                <span className="font-mono text-[var(--color-text-secondary)]">
                  enterprise.local
                </span>
              </div>

              <div className="flex items-center justify-between px-2 py-1.5 text-[10px]">
                <span className="text-[var(--color-text-muted)]">
                  Account Role
                </span>

                <span className="text-[var(--color-severity-healthy)] font-medium capitalize">
                  {(session?.user as any)?.role || 'Analyst'}
                </span>
              </div>

              <div className="pt-2 border-t border-[var(--color-border-subtle)] space-y-1.5">

                <Link
                  href="/settings"
                  onClick={() => setActiveDropdown(null)}
                  className="w-full flex items-center gap-2 px-3 py-2 text-[10px] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] rounded-lg transition-colors"
                >
                  <SettingsIcon size={12} />
                  Preferences
                </Link>

                <button
                  onClick={() =>
                    signOut({ callbackUrl: '/login' })
                  }
                  className="w-full flex items-center gap-2 px-3 py-2 text-[10px] font-medium rounded-lg text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-bg)] transition-colors"
                >
                  <LogOut size={12} />
                  Sign Out
                </button>

              </div>

            </div>
          </div>
        )}

      </div>
    </header>
  );
}