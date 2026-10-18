'use client';

import { useState, useRef, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useSession, signOut } from 'next-auth/react';
import {
  Search, Bell, Wifi, Check, Clock,
  ExternalLink, Settings as SettingsIcon, LogOut, Laptop,
  Menu, Smartphone, Copy, CheckCheck, QrCode, Sparkles
} from 'lucide-react';
import clsx from 'clsx';
import Link from 'next/link';

interface TopBarProps {
  title: string;
  description?: string;
  onOpenMobileMenu?: () => void;
}

export default function TopBar({ title, description, onOpenMobileMenu }: TopBarProps) {
  const router = useRouter();
  const { data: session } = useSession();
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeDropdown, setActiveDropdown] = useState<'notifications' | 'api' | 'user' | null>(null);
  const [copied, setCopied] = useState(false);
  const [syncUrl, setSyncUrl] = useState('https://garuda-mail.vercel.app');

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

  useEffect(() => {
    if (typeof window !== 'undefined') {
      if (!window.location.hostname.includes('localhost') && window.location.hostname !== '127.0.0.1') {
        setSyncUrl(window.location.origin);
      }
    }
  }, []);

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(syncUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };

  const unreadCount = notifications.filter(n => n.unread).length;

  const userName = session?.user?.name || 'User';
  const userEmail = session?.user?.email || '';
  const userInitials = userName
    .split(' ')
    .map(w => w[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();

  return (
    <header className="sticky top-0 z-30 h-[56px] flex items-center justify-between px-3 sm:px-6 surface-1 border-b border-default backdrop-blur-md">
      {/* ── Left: Mobile Hamburger & Page Context ── */}
      <div className="flex items-center gap-2 sm:gap-3 min-w-0">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          className="md:hidden flex items-center justify-center w-8 h-8 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] transition-colors"
          aria-label="Open navigation menu"
        >
          <Menu size={18} />
        </button>

        <div className="min-w-0">
          <h1 className="text-[14px] sm:text-[15px] font-semibold text-[var(--color-text-primary)] truncate">{title}</h1>
          {description && (
            <p className="hidden sm:block text-[11px] text-[var(--color-text-muted)] truncate">{description}</p>
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
                  placeholder="Search emails, subject..."
                  autoFocus
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && searchQuery.trim()) {
                      router.push(`/inbox?search=${encodeURIComponent(searchQuery.trim())}`);
                    }
                  }}
                  onBlur={() => { if (!searchQuery) setSearchOpen(false); }}
                  className="w-[160px] sm:w-[220px] md:w-[280px] h-8 pl-8 pr-3 text-[12px] rounded-md bg-[var(--color-surface-2)] border border-default text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
                />
              </div>
              <kbd className="hidden md:inline-flex items-center px-1.5 h-5 text-[10px] font-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] border border-default rounded">
                ESC
              </kbd>
            </div>
          ) : (
            <button
              onClick={() => setSearchOpen(true)}
              className="flex items-center gap-1.5 h-8 px-2 sm:px-3 text-[12px] text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] bg-[var(--color-surface-2)] border border-default rounded-md hover:border-[var(--color-border-active)] transition-colors"
              title="Search emails"
            >
              <Search size={14} />
              <span className="hidden sm:inline">Search</span>
              <kbd className="hidden md:inline-flex items-center px-1.5 h-4 text-[10px] font-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] rounded">
                ⌘K
              </kbd>
            </button>
          )}
        </div>

        <div className="w-px h-5 bg-[var(--color-border)] mx-1 sm:mx-2" />

        {/* Laptop & Mobile Sync Button */}
        <div className="relative">
          <button
            title="Laptop & Mobile Multi-Device Sync"
            onClick={() => setActiveDropdown(activeDropdown === 'api' ? null : 'api')}
            className={clsx(
              "relative flex items-center justify-center gap-1.5 h-8 px-2.5 rounded-lg transition-all",
              activeDropdown === 'api'
                ? "bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-sm"
                : "text-[var(--color-text-muted)] hover:text-sky-300 hover:bg-sky-500/10 border border-transparent"
            )}
          >
            <Laptop size={14} className="text-sky-400 hidden sm:inline" />
            <Smartphone size={14} className="text-cyan-400" />
            <span className="text-[10px] font-semibold text-cyan-300 hidden lg:inline">Cross-Device</span>
          </button>
        </div>

        {/* Notifications */}
        <div className="relative">
          <button
            title="Security Notifications"
            onClick={() => setActiveDropdown(activeDropdown === 'notifications' ? null : 'notifications')}
            className={clsx(
              "relative flex items-center justify-center w-8 h-8 rounded-lg transition-colors",
              activeDropdown === 'notifications' ? "bg-[var(--color-surface-3)] text-white" : "text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)]"
            )}
          >
            <Bell size={16} />
            {unreadCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center w-4 h-4 text-[9px] font-bold text-white bg-gradient-to-r from-rose-500 to-pink-500 rounded-full shadow-[0_0_8px_rgba(244,63,94,0.5)]">
                {unreadCount}
              </span>
            )}
          </button>
        </div>

        {/* User Avatar Button with Jewel Gradient Ring */}
        <div className="relative">
          <button
            title={`Logged in as ${userName}`}
            onClick={() => setActiveDropdown(activeDropdown === 'user' ? null : 'user')}
            className="flex items-center justify-center w-8 h-8 rounded-full hover:ring-2 hover:ring-sky-400/50 transition-all cursor-pointer"
          >
            <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-sky-400 via-indigo-500 to-purple-500 p-[1.5px] shadow-sm">
              <div className="w-full h-full rounded-full bg-[#0D121F] flex items-center justify-center">
                <span className="text-[10px] font-bold text-sky-300">{userInitials}</span>
              </div>
            </div>
          </button>
        </div>

        {/* ── Dropdown: Notifications ── */}
        {activeDropdown === 'notifications' && (
          <div className="absolute right-2 sm:right-6 top-[54px] w-[calc(100vw-24px)] max-w-sm sm:w-80 card bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-150">
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

        {/* ── Dropdown: Laptop & Mobile Multi-Device Sync ── */}
        {activeDropdown === 'api' && (
          <div className="absolute right-2 sm:right-10 top-[54px] w-[calc(100vw-24px)] max-w-sm sm:w-84 card bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl p-4 space-y-3 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--color-border)]">
              <div className="flex items-center gap-1.5 font-semibold text-[12px] text-[var(--color-text-primary)]">
                <Laptop size={14} className="text-[var(--color-accent)]" />
                <Smartphone size={14} className="text-cyan-400" />
                <span>Laptop &amp; Mobile Sync</span>
              </div>
              <span className="inline-flex items-center gap-1 text-[10px] text-[var(--color-severity-healthy)] font-bold bg-emerald-950/60 border border-emerald-500/20 px-1.5 py-0.5 rounded">
                <Check size={11} /> Cloud Synced
              </span>
            </div>

            {/* Live Cloud Link Card */}
            <div className="p-2.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">
                  Live Cloud Production URL
                </span>
                <span className="text-[10px] text-cyan-400 font-mono">Any Device</span>
              </div>
              <div className="flex items-center justify-between gap-2 p-1.5 rounded bg-[var(--color-surface-3)] border border-default">
                <span className="text-[11px] font-mono text-cyan-300 truncate">
                  {syncUrl}
                </span>
                <button
                  type="button"
                  onClick={handleCopyLink}
                  className="flex items-center gap-1 px-2 py-1 text-[10px] font-semibold rounded bg-[var(--color-accent-dim)] text-[var(--color-accent)] hover:bg-[#154c6e] transition-colors flex-shrink-0"
                >
                  {copied ? <CheckCheck size={11} /> : <Copy size={11} />}
                  <span>{copied ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>

            {/* Mobile Camera Scan QR Graphic */}
            <div className="p-3 rounded-lg bg-gradient-to-br from-slate-900 to-[#111827] border border-cyan-500/20 text-center space-y-2">
              <div className="flex items-center justify-center gap-1.5 text-[11px] font-semibold text-cyan-300">
                <QrCode size={13} />
                <span>Open on Mobile Camera</span>
              </div>
              <div className="inline-block p-2 bg-white rounded-lg shadow-md">
                {/* Real, scannable QR code linking to current deployment */}
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(syncUrl)}&format=svg`}
                  alt="Garuda Mail Mobile Link QR Code"
                  width="100"
                  height="100"
                  className="w-24 h-24 mx-auto block"
                />
              </div>
              <p className="text-[10px] text-slate-400">
                Point your phone camera at the QR code to open Garuda Mail immediately.
              </p>
            </div>

            {/* PWA Home Screen Instructions */}
            <div className="space-y-1.5 text-[11px] pt-1">
              <span className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] font-semibold flex items-center gap-1">
                <Sparkles size={11} className="text-amber-400" />
                Install as Mobile App (PWA)
              </span>
              <div className="grid grid-cols-2 gap-2 text-[10px]">
                <div className="p-2 rounded bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
                  <div className="font-semibold text-slate-200">🍏 Apple iPhone</div>
                  <div className="text-slate-400 mt-0.5">Safari Share ➔ &quot;Add to Home Screen&quot;</div>
                </div>
                <div className="p-2 rounded bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
                  <div className="font-semibold text-slate-200">🤖 Android</div>
                  <div className="text-slate-400 mt-0.5">Chrome Menu ➔ &quot;Install App&quot;</div>
                </div>
              </div>
            </div>

            <div className="pt-2 border-t border-[var(--color-border)] flex items-center justify-between text-[10px] text-slate-400">
              <span>Local Wi-Fi LAN:</span>
              <span className="font-mono text-cyan-400">http://192.168.1.3:3000</span>
            </div>
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
                <span className="text-mono text-[var(--color-text-secondary)]">
                  {userEmail.includes('@') ? userEmail.split('@')[1] : 'garudamail.local'}
                </span>
              </div>
              <div className="flex items-center justify-between text-[var(--color-text-muted)] py-1">
                <span>Account Role:</span>
                <span className="text-[var(--color-severity-healthy)] font-medium capitalize">
                  {session?.user?.role || 'Analyst'}
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
