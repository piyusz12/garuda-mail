'use client';

import { useState, useRef, useEffect } from 'react';
import { useSession, signOut } from 'next-auth/react';
import {
  Search, Bell, Wifi, Activity, Check, Clock,
  ExternalLink, Settings as SettingsIcon, LogOut, Laptop,
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
  const [activeDropdown, setActiveDropdown] = useState<'notifications' | 'api' | 'user' | null>(null);

  const [notifications, setNotifications] = useState([
    { id: 1, title: 'STARTTLS Downgrade Detected', desc: 'Plaintext IMAP session without TLS on port 143', time: '12m ago', unread: true, sev: 'critical' },
    { id: 2, title: 'Certificate Expiry Warning', desc: 'mail.example.com certificate expires in 18 days', time: '1h ago', unread: true, sev: 'high' },
    { id: 3, title: 'Rare JA4 Fingerprint Observed', desc: 'New rare JA4 signature seen on SMTP-0192', time: '3h ago', unread: false, sev: 'medium' },
  ]);

  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setActiveDropdown(null);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const unreadCount = notifications.filter(n => n.unread).length;

  const userName = session?.user?.name || 'Garuda Analyst';
  const userEmail = session?.user?.email || 'analyst@enterprise.local';
  const userInitials = userName
    .split(' ')
    .map(w => w[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();

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
      <div className="flex items-center gap-1" ref={dropdownRef}>
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
                  placeholder="Search emails, subject, sender..."
                  autoFocus
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && searchQuery.trim()) {
                      window.location.href = `/inbox?search=${encodeURIComponent(searchQuery.trim())}`;
                    }
                  }}
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
              <span className="hidden md:inline">Search emails</span>
              <kbd className="hidden md:inline-flex items-center px-1.5 h-4 text-[10px] font-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] rounded">
                ⌘K
              </kbd>
            </button>
          )}
        </div>

        <div className="w-px h-5 bg-[var(--color-border)] mx-2" />

        {/* Multi-PC / Network Info */}
        <div className="relative">
          <button
            title="Multi-PC Connection Diagnostics"
            onClick={() => setActiveDropdown(activeDropdown === 'api' ? null : 'api')}
            className={clsx(
              "relative flex items-center justify-center w-8 h-8 rounded-md transition-colors",
              activeDropdown === 'api' ? "bg-[var(--color-surface-3)] text-white" : "text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)]"
            )}
          >
            <Laptop size={15} className="text-[var(--color-accent)]" />
          </button>
        </div>

        {/* Notifications */}
        <div className="relative">
          <button
            title="Security Notifications"
            onClick={() => setActiveDropdown(activeDropdown === 'notifications' ? null : 'notifications')}
            className={clsx(
              "relative flex items-center justify-center w-8 h-8 rounded-md transition-colors",
              activeDropdown === 'notifications' ? "bg-[var(--color-surface-3)] text-white" : "text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)]"
            )}
          >
            <Bell size={16} />
            {unreadCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center w-4 h-4 text-[9px] font-bold text-white bg-[var(--color-severity-critical)] rounded-full animate-pulse">
                {unreadCount}
              </span>
            )}
          </button>
        </div>

        {/* User Avatar Button */}
        <div className="relative">
          <button
            title={`Logged in as ${userName}`}
            onClick={() => setActiveDropdown(activeDropdown === 'user' ? null : 'user')}
            className="flex items-center justify-center w-8 h-8 rounded-md hover:bg-[var(--color-surface-2)] transition-colors"
          >
            <div className="w-7 h-7 rounded-full bg-[var(--color-accent-dim)] border border-[rgba(56,189,248,0.25)] flex items-center justify-center">
              <span className="text-[10px] font-bold text-[var(--color-accent)]">{userInitials}</span>
            </div>
          </button>
        </div>

        {/* ── Dropdown: Notifications ── */}
        {activeDropdown === 'notifications' && (
          <div className="absolute right-6 top-[54px] w-80 card bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-150">
            <div className="p-3 border-b border-[var(--color-border)] flex items-center justify-between bg-[var(--color-surface-2)]">
              <div className="flex items-center gap-1.5 font-semibold text-[12px] text-[var(--color-text-primary)]">
                <Bell size={13} className="text-[var(--color-accent)]" /> Security Alerts ({notifications.length})
              </div>
              {unreadCount > 0 && (
                <button
                  onClick={() => setNotifications(notifications.map(n => ({ ...n, unread: false })))}
                  className="text-[10px] text-[var(--color-accent)] hover:underline"
                >
                  Mark all read
                </button>
              )}
            </div>
            <div className="divide-y divide-[var(--color-border-subtle)] max-h-72 overflow-y-auto">
              {notifications.map(n => (
                <div key={n.id} className={clsx("p-3 hover:bg-[var(--color-surface-2)] transition-colors", n.unread && "bg-[rgba(56,189,248,0.03)]")}>
                  <div className="flex items-start justify-between gap-2">
                    <span className={clsx(
                      "text-[11px] font-semibold",
                      n.sev === 'critical' ? 'text-[var(--color-severity-critical)]' : n.sev === 'high' ? 'text-[var(--color-severity-high)]' : 'text-[var(--color-text-primary)]'
                    )}>
                      {n.title}
                    </span>
                    <span className="text-[9px] text-[var(--color-text-dim)] flex items-center gap-0.5 whitespace-nowrap">
                      <Clock size={10} /> {n.time}
                    </span>
                  </div>
                  <p className="text-[11px] text-[var(--color-text-muted)] mt-1">{n.desc}</p>
                </div>
              ))}
            </div>
            <div className="p-2 border-t border-[var(--color-border)] bg-[var(--color-surface-2)] text-center">
              <Link href="/findings" onClick={() => setActiveDropdown(null)} className="text-[11px] text-[var(--color-accent)] hover:underline inline-flex items-center gap-1">
                View all security findings <ExternalLink size={10} />
              </Link>
            </div>
          </div>
        )}

        {/* ── Dropdown: Multi-PC & Diagnostics ── */}
        {activeDropdown === 'api' && (
          <div className="absolute right-14 top-[54px] w-80 card bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl p-4 space-y-3 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--color-border)]">
              <span className="text-[12px] font-semibold text-[var(--color-text-primary)] flex items-center gap-1.5">
                <Wifi size={13} className="text-[var(--color-severity-healthy)]" /> Multi-PC Access Info
              </span>
              <span className="inline-flex items-center gap-1 text-[10px] text-[var(--color-severity-healthy)] font-bold">
                <Check size={12} /> Operational
              </span>
            </div>
            <div className="space-y-2 text-[11px]">
              <div className="flex justify-between py-1 border-b border-[var(--color-border-subtle)]">
                <span className="text-[var(--color-text-muted)]">This PC Access</span>
                <span className="text-mono text-[var(--color-accent)] font-medium">http://localhost:3000</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[var(--color-border-subtle)]">
                <span className="text-[var(--color-text-muted)]">2nd PC Network URL</span>
                <span className="text-mono text-[var(--color-severity-healthy)] font-bold">http://192.168.1.3:3000</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[var(--color-border-subtle)]">
                <span className="text-[var(--color-text-muted)]">Database Engine</span>
                <span className="text-mono text-[var(--color-text-primary)]">SQLite (dev.db synchronized)</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[var(--color-text-muted)]">Session Auth</span>
                <span className="text-mono text-[var(--color-severity-healthy)]">NextAuth Active</span>
              </div>
            </div>
            <p className="text-[10px] text-[var(--color-text-dim)] pt-1">
              Open the 2nd PC Network URL on your other computer connected to the same Wi-Fi to test cross-device mail.
            </p>
          </div>
        )}

        {/* ── Dropdown: User Profile ── */}
        {activeDropdown === 'user' && (
          <div className="absolute right-4 top-[54px] w-64 card bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl p-4 space-y-3 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
            <div className="flex items-center gap-2.5 pb-3 border-b border-[var(--color-border)]">
              <div className="w-8 h-8 rounded-full bg-[var(--color-accent-dim)] border border-[rgba(56,189,248,0.25)] flex items-center justify-center font-bold text-[12px] text-[var(--color-accent)]">
                {userInitials}
              </div>
              <div className="min-w-0">
                <div className="text-[12px] font-semibold text-[var(--color-text-primary)] truncate">{userName}</div>
                <div className="text-[10px] text-[var(--color-text-dim)] truncate">{userEmail}</div>
              </div>
            </div>
            <div className="space-y-1 text-[11px]">
              <div className="flex items-center justify-between text-[var(--color-text-muted)] py-1">
                <span>Domain:</span>
                <span className="text-mono text-[var(--color-text-secondary)]">enterprise.local</span>
              </div>
              <div className="flex items-center justify-between text-[var(--color-text-muted)] py-1">
                <span>Account Role:</span>
                <span className="text-[var(--color-severity-healthy)] font-medium capitalize">
                  {(session?.user as any)?.role || 'Analyst'}
                </span>
              </div>
            </div>
            <Link
              href="/settings"
              onClick={() => setActiveDropdown(null)}
              className="btn btn-secondary w-full text-[11px] py-1.5 flex items-center justify-center gap-1.5 mt-2"
            >
              <SettingsIcon size={12} /> Preferences
            </Link>
            <button
              onClick={() => signOut({ callbackUrl: '/login' })}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 text-[11px] font-medium rounded-md text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-bg)] border border-[rgba(239,68,68,0.2)] transition-colors"
            >
              <LogOut size={12} />
              Sign Out
            </button>
          </div>
        )}

      </div>
    </header>
  );
}
