'use client';

import { useState, useMemo, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Inbox as InboxIcon, Star, Paperclip, AlertTriangle,
  ChevronRight, Lock, LockOpen, Filter, RefreshCw, Network,
  ShieldCheck, AlertCircle, ShieldAlert, Activity
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { getEmailsByFolder } from '@/lib/mock/emails';
import Link from 'next/link';
import clsx from 'clsx';
import type { EmailMessage, SecurityLevel } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function InboxPage() {
  const [emails, setEmails] = useState<EmailMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [securityFilter, setSecurityFilter] = useState<SecurityLevel | 'all'>('all');
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const fetchEmails = useCallback(async (isSilent = false) => {
    if (!isSilent) setRefreshing(true);
    try {
      const res = await fetch('/api/emails?folder=inbox');
      if (res.ok) {
        const data = await res.json();
        if (data.emails && Array.isArray(data.emails)) {
          const mapped: EmailMessage[] = data.emails.map((e: any) => {
            const secLevel: SecurityLevel =
              e.riskScore !== null && e.riskScore !== undefined
                ? e.riskScore >= 75 ? 'critical' : e.riskScore >= 40 ? 'warning' : 'secure'
                : e.tlsVersion ? 'secure' : 'critical';

            const fromName = e.from?.name || e.fromExternal || 'Unknown Sender';
            const fromEmail = e.from?.email || e.fromExternal || 'unknown@domain.com';
            const domain = fromEmail.includes('@') ? fromEmail.split('@')[1] : 'enterprise.local';

            return {
              id: e.id,
              folder: 'inbox',
              from: {
                name: fromName,
                email: fromEmail,
                domain,
              },
              to: e.recipients?.map((r: any) => ({
                name: r.name || r.user?.name || r.address,
                email: r.address || r.user?.email || '',
                domain: (r.address || '').split('@')[1] || '',
              })) || [],
              subject: e.subject || '(No Subject)',
              preview: e.preview || e.body?.slice(0, 140) || '',
              body: e.body || '',
              timestamp: e.sentAt || e.createdAt,
              read: e._recipient ? e._recipient.read : true,
              starred: e._recipient ? e._recipient.starred : e.starred || false,
              attachments: e.attachments || [],
              security: {
                level: secLevel,
                tlsVersion: e.tlsVersion || null,
                cipher: e.cipher || null,
                forwardSecrecy: e.forwardSecrecy ?? null,
                starttls: e.starttls ?? null,
                certificateStatus: e.tlsVersion ? 'valid' : null,
                riskScore: e.riskScore ?? null,
                anomalyScore: null,
                findingsCount: e.riskScore && e.riskScore > 50 ? 2 : 0,
                sessionId: null,
              },
              threadId: e.threadId || `THREAD-${e.id}`,
              labels: [],
            };
          });
          setEmails(mapped);
        }
      } else {
        // Fallback to local data if unauthorized or initializing
        setEmails(getEmailsByFolder('inbox'));
      }
    } catch {
      setEmails(getEmailsByFolder('inbox'));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchEmails();
    // Auto-poll every 2 seconds for instant real-time multi-PC synchronization
    const interval = setInterval(() => {
      fetchEmails(true);
    }, 2000);
    return () => clearInterval(interval);
  }, [fetchEmails]);

  const handleToggleStar = async (e: React.MouseEvent, emailId: string, currentStarred: boolean) => {
    e.preventDefault();
    e.stopPropagation();

    // Optimistic UI update
    setEmails(prev => prev.map(em => em.id === emailId ? { ...em, starred: !currentStarred } : em));

    try {
      await fetch(`/api/emails/${emailId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ starred: !currentStarred }),
      });
    } catch (err) {
      console.error('Failed to toggle star', err);
    }
  };

  const filtered = useMemo(() => {
    if (securityFilter === 'all') return emails;
    return emails.filter(e => e.security.level === securityFilter);
  }, [emails, securityFilter]);

  const unreadCount = emails.filter(e => !e.read).length;
  const criticalCount = emails.filter(e => e.security.level === 'critical').length;
  const secureCount = emails.filter(e => e.security.level === 'secure').length;

  const messagesWithRisk = emails.filter(e => e.security.riskScore !== null);
  const avgRisk = messagesWithRisk.length > 0
    ? Math.round(messagesWithRisk.reduce((acc, curr) => acc + (curr.security.riskScore || 0), 0) / messagesWithRisk.length)
    : 0;

  return (
    <AppShell
      title="Inbox"
      description={`Security Intelligence • ${emails.length} messages • ${unreadCount} unread • Auto-Sync Active`}
    >
      <motion.div initial="initial" animate="animate" className="space-y-6 max-w-[1400px] mx-auto pb-12">

        {/* Inbox Statistics */}
        <motion.div {...fadeUp} className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard label="Total Indexed" value={emails.length} />
          <StatCard label="Unread" value={unreadCount} highlight={unreadCount > 0 ? 'accent' : 'none'} />
          <StatCard label="Critical Threats" value={criticalCount} highlight={criticalCount > 0 ? 'critical' : 'none'} />
          <StatCard label="Secure Connections" value={secureCount} highlight="secure" />
          <StatCard label="Avg Risk Score" value={avgRisk > 0 ? avgRisk : '--'} highlight={avgRisk > 50 ? 'warning' : 'none'} />
        </motion.div>

        {/* Security Filter Toolbar */}
        <motion.div {...fadeUp} className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[var(--color-surface-1)] border border-[var(--color-border)] p-2 rounded-xl shadow-sm">
          <div className="flex items-center gap-1 overflow-x-auto pb-1 sm:pb-0 hide-scrollbar px-1">
            <div className="flex items-center gap-1.5 px-3 border-r border-[var(--color-border-subtle)] mr-1">
              <Filter size={14} className="text-[var(--color-text-dim)]" />
              <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-dim)] font-semibold">Triage</span>
            </div>
            {[
              { id: 'all' as const, label: 'All Events', count: emails.length, icon: <Activity size={14} /> },
              { id: 'critical' as const, label: 'Critical', count: criticalCount, icon: <ShieldAlert size={14} /> },
              { id: 'warning' as const, label: 'Warning', count: emails.filter(e => e.security.level === 'warning').length, icon: <AlertCircle size={14} /> },
              { id: 'secure' as const, label: 'Secure', count: secureCount, icon: <ShieldCheck size={14} /> },
            ].map(f => {
              const isActive = securityFilter === f.id;
              return (
                <button
                  key={f.id}
                  onClick={() => setSecurityFilter(f.id)}
                  className={clsx(
                    'relative px-3 py-2 text-[12px] font-medium rounded-lg transition-all duration-200 flex items-center gap-2 whitespace-nowrap',
                    isActive
                      ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] shadow-sm'
                      : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)]'
                  )}
                >
                  <span className={clsx("opacity-70 transition-colors",
                    isActive && f.id === 'critical' ? 'text-[var(--color-severity-critical)]' :
                    isActive && f.id === 'secure' ? 'text-[var(--color-severity-healthy)]' :
                    isActive && f.id === 'warning' ? 'text-[var(--color-severity-high)]' : ''
                  )}>
                    {f.icon}
                  </span>
                  {f.label}
                  <span className={clsx(
                    "text-[10px] px-1.5 py-0.5 rounded-full font-mono min-w-[20px] text-center transition-colors",
                    isActive ? "bg-[var(--color-surface-1)] text-[var(--color-text-primary)] border border-[var(--color-border)]" : "bg-transparent text-[var(--color-text-dim)]"
                  )}>{f.count}</span>
                  {isActive && (
                    <motion.div layoutId="activeFilter" className="absolute inset-0 border border-[var(--color-border-subtle)] rounded-lg pointer-events-none" />
                  )}
                </button>
              )
            })}
          </div>

          <div className="flex items-center px-2 sm:px-1 sm:ml-auto">
            <button
              onClick={() => fetchEmails(false)}
              disabled={refreshing}
              className="flex items-center gap-2 px-4 py-2 text-[12px] font-medium rounded-lg bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-all shadow-sm group"
              title="Force Sync"
            >
              <RefreshCw size={14} className={clsx("transition-transform group-hover:rotate-180 duration-500", refreshing && 'animate-spin text-[var(--color-accent)]')} />
              <span>{refreshing ? 'Syncing...' : 'Live Sync'}</span>
              <div className="relative flex h-2 w-2 ml-1">
                <span className={clsx("absolute inline-flex h-full w-full rounded-full opacity-75", refreshing ? "animate-ping bg-[var(--color-accent)]" : "bg-[var(--color-severity-healthy)]")}></span>
                <span className={clsx("relative inline-flex rounded-full h-2 w-2", refreshing ? "bg-[var(--color-accent)]" : "bg-[var(--color-severity-healthy)]")}></span>
              </div>
            </button>
          </div>
        </motion.div>

        {/* Email List */}
        <motion.div {...fadeUp} className="bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-xl overflow-hidden shadow-sm min-h-[400px] flex flex-col">
          {loading ? (
            <div className="flex-1 flex flex-col items-center justify-center py-20 text-[13px] text-[var(--color-text-muted)]">
              <RefreshCw size={24} className="animate-spin mb-4 text-[var(--color-accent)]" />
              <div className="font-medium tracking-wide">INITIALIZING WORKSPACE...</div>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center py-24 text-center px-4">
              <div className="relative mb-6">
                <div className="absolute inset-0 bg-[var(--color-severity-healthy)]/20 blur-xl rounded-full" />
                <div className="relative flex items-center justify-center w-16 h-16 rounded-2xl bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] shadow-lg">
                  <ShieldCheck className="text-[var(--color-severity-healthy)]" size={32} />
                </div>
              </div>
              <h3 className="text-[18px] font-semibold text-[var(--color-text-primary)] mb-2 tracking-tight">Zero findings in current view</h3>
              <p className="text-[14px] text-[var(--color-text-muted)] max-w-md mb-6">
                No messages match the active filter criteria. Auto-sync is engaged and monitoring for incoming events.
              </p>
              {securityFilter !== 'all' && (
                <button
                  onClick={() => setSecurityFilter('all')}
                  className="px-5 py-2.5 bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] rounded-lg text-[13px] font-medium transition-all text-[var(--color-text-primary)] shadow-sm flex items-center gap-2"
                >
                  <Filter size={14} className="text-[var(--color-text-muted)]" />
                  Clear Filters
                </button>
              )}
            </div>
          ) : (
            <div className="flex-1 flex flex-col divide-y divide-[var(--color-border-subtle)]">
              {filtered.map((email, i) => (
                <EmailRow
                  key={email.id}
                  email={email}
                  index={i}
                  isHovered={hoveredId === email.id}
                  onHover={setHoveredId}
                  onToggleStar={handleToggleStar}
                />
              ))}
            </div>
          )}
        </motion.div>
      </motion.div>
    </AppShell>
  );
}

function StatCard({ label, value, highlight = 'none' }: { label: string, value: string | number, highlight?: 'none' | 'accent' | 'critical' | 'secure' | 'warning' }) {
  const highlightStyles = {
    none: 'text-[var(--color-text-primary)]',
    accent: 'text-[var(--color-accent)]',
    critical: 'text-[var(--color-severity-critical)] drop-shadow-[0_0_8px_rgba(239,68,68,0.4)]',
    secure: 'text-[var(--color-severity-healthy)]',
    warning: 'text-[var(--color-severity-high)]',
  };

  const borderStyles = {
    none: 'border-[var(--color-border-subtle)]',
    accent: 'border-[var(--color-accent)]/30',
    critical: 'border-[var(--color-severity-critical)]/30',
    secure: 'border-[var(--color-severity-healthy)]/30',
    warning: 'border-[var(--color-severity-high)]/30',
  }

  return (
    <div className={clsx(
      "flex flex-col p-4 rounded-xl border bg-[var(--color-surface-1)] shadow-sm relative overflow-hidden transition-all duration-300 hover:bg-[var(--color-surface-2)]",
      borderStyles[highlight]
    )}>
      {highlight !== 'none' && (
        <div className={clsx(
          "absolute -top-10 -right-10 w-24 h-24 rounded-full blur-2xl opacity-20 pointer-events-none transition-opacity duration-500",
          highlight === 'critical' ? 'bg-[var(--color-severity-critical)] opacity-30' :
          highlight === 'accent' ? 'bg-[var(--color-accent)]' :
          highlight === 'secure' ? 'bg-[var(--color-severity-healthy)]' :
          'bg-[var(--color-severity-high)]'
        )} />
      )}
      <span className="text-[11px] font-semibold text-[var(--color-text-dim)] uppercase tracking-wider mb-2 relative z-10">{label}</span>
      <span className={clsx("text-3xl font-bold tracking-tight relative z-10", highlightStyles[highlight])}>{value}</span>
    </div>
  );
}

function EmailRow({
  email,
  index,
  isHovered,
  onHover,
  onToggleStar,
}: {
  email: EmailMessage;
  index: number;
  isHovered: boolean;
  onHover: (id: string | null) => void;
  onToggleStar: (e: React.MouseEvent, id: string, starred: boolean) => void;
}) {
  const secLvl = email.security.level || 'unknown';
  const isCritical = secLvl === 'critical';
  const isWarning = secLvl === 'warning';
  const isSecure = secLvl === 'secure';

  const secColor = isCritical ? 'var(--color-severity-critical)' :
                   isWarning ? 'var(--color-severity-high)' :
                   isSecure ? 'var(--color-severity-healthy)' : 'var(--color-text-dim)';

  const secBg = isCritical ? 'rgba(239, 68, 68, 0.08)' :
                isWarning ? 'rgba(245, 158, 11, 0.05)' :
                isSecure ? 'rgba(16, 185, 129, 0.05)' : 'var(--color-surface-2)';

  const secBorder = isCritical ? 'rgba(239, 68, 68, 0.3)' :
                    isWarning ? 'rgba(245, 158, 11, 0.3)' :
                    isSecure ? 'rgba(16, 185, 129, 0.3)' : 'var(--color-border-subtle)';

  const SecIcon = isCritical ? ShieldAlert :
                  isWarning ? AlertTriangle :
                  isSecure ? ShieldCheck : Network;

  return (
    <Link
      href={`/inbox/${email.id}`}
      className={clsx(
        'relative flex items-stretch transition-all duration-200 group bg-[var(--color-surface-1)]',
        !email.read && 'bg-[var(--color-surface-2)]',
        isHovered && '!bg-[var(--color-surface-3)]',
      )}
      onMouseEnter={() => onHover(email.id)}
      onMouseLeave={() => onHover(null)}
    >
      {/* Selection indicator line */}
      <div className={clsx(
        "absolute left-0 top-0 bottom-0 w-[3px] transition-colors duration-200 z-10",
        isHovered ? "bg-[var(--color-accent)]" : !email.read ? "bg-[var(--color-accent-dim)]" : "bg-transparent"
      )} />

      <div className="flex items-center w-full px-5 py-4 gap-4 relative z-0">

        {/* Status & Star */}
        <div className="flex flex-col items-center gap-2 w-8 flex-shrink-0">
          <div
            className="flex items-center justify-center w-7 h-7 rounded-md shadow-sm transition-all"
            style={{
              backgroundColor: isCritical ? secBg : 'var(--color-surface-2)',
              border: `1px solid ${isCritical ? secBorder : 'var(--color-border-subtle)'}`,
              color: secColor,
              boxShadow: isCritical && !email.read ? `0 0 10px ${secColor}40` : 'none'
            }}
            title={`Security: ${secLvl}`}
          >
            <SecIcon size={14} />
          </div>
          <button
            type="button"
            onClick={(e) => onToggleStar(e, email.id, email.starred)}
            className="p-1 rounded-md hover:bg-[var(--color-surface-3)] transition-colors"
          >
            <Star
              size={14}
              className={clsx(
                email.starred
                  ? 'text-[var(--color-severity-high)] fill-[var(--color-severity-high)]'
                  : 'text-[var(--color-text-dim)] hover:text-[var(--color-text-muted)] group-hover:text-[var(--color-text-secondary)]'
              )}
            />
          </button>
        </div>

        {/* Main Content */}
        <div className="flex-1 min-w-0 flex flex-col gap-1.5">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 truncate">
              <span className={clsx(
                'text-[14px] truncate transition-colors',
                !email.read ? 'font-semibold text-[var(--color-text-primary)]' : 'font-medium text-[var(--color-text-secondary)] group-hover:text-[var(--color-text-primary)]'
              )}>
                {email.from.name}
              </span>
              <span className="text-[11px] text-[var(--color-text-dim)] font-mono bg-[var(--color-surface-2)] px-1.5 py-0.5 rounded border border-[var(--color-border-subtle)] hidden sm:inline-block">
                {email.from.domain}
              </span>
              {!email.read && (
                <span className="px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider bg-[var(--color-accent-dim)] text-[var(--color-accent)] rounded-sm border border-[var(--color-accent)]/20">
                  New
                </span>
              )}
            </div>
            <span className="text-[12px] font-medium text-[var(--color-text-dim)] tabular-nums flex-shrink-0 group-hover:text-[var(--color-text-secondary)] transition-colors">
              {formatEmailTime(email.timestamp)}
            </span>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 truncate">
            <span className={clsx(
              'text-[14px] truncate sm:max-w-[45%]',
              !email.read ? 'font-medium text-[var(--color-text-primary)]' : 'text-[var(--color-text-secondary)] group-hover:text-[var(--color-text-primary)] transition-colors'
            )}>
              {email.subject}
            </span>
            <span className="text-[13px] text-[var(--color-text-muted)] truncate flex-1 font-light">
              {email.preview}
            </span>
          </div>
        </div>

        {/* Security Metadata Tags */}
        <div className="hidden lg:flex items-center justify-end gap-2 w-[280px] xl:w-[320px] flex-shrink-0">
          {email.attachments.length > 0 && (
            <div className="flex items-center justify-center w-7 h-7 rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] text-[var(--color-text-dim)]" title={`${email.attachments.length} attachment(s)`}>
              <Paperclip size={13} />
            </div>
          )}

          {email.security.findingsCount > 0 && (
            <span className="flex items-center gap-1.5 text-[11px] font-medium px-2 py-1 rounded-md border"
              style={{
                color: secColor,
                backgroundColor: `${secColor}10`,
                borderColor: `${secColor}30`
              }}>
              <AlertTriangle size={12} />
              <span>{email.security.findingsCount} findings</span>
            </span>
          )}

          {email.security.tlsVersion ? (
            <span className="flex items-center gap-1.5 text-[11px] font-mono px-2 py-1 rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]"
              style={{
                color: email.security.tlsVersion === 'TLS 1.3' ? 'var(--color-severity-healthy)' : 'var(--color-text-secondary)'
              }}>
              <Lock size={11} />
              {email.security.tlsVersion}
            </span>
          ) : secLvl !== 'unknown' ? (
            <span className="flex items-center gap-1.5 text-[11px] font-mono font-medium px-2 py-1 rounded-md bg-[var(--color-severity-critical-bg)] border border-[var(--color-severity-critical)]/30 text-[var(--color-severity-critical)]">
              <LockOpen size={11} />
              NO TLS
            </span>
          ) : null}

          {email.security.riskScore !== null && (
            <RiskPill score={email.security.riskScore} />
          )}
        </div>

        {/* Action Chevron */}
        <div className="flex-shrink-0 ml-1 sm:ml-2">
          <div className={clsx(
            "flex items-center justify-center w-8 h-8 rounded-full transition-all duration-300",
            isHovered ? "bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]" : "bg-transparent border border-transparent"
          )}>
            <ChevronRight
              size={16}
              className={clsx(
                'transition-all duration-300',
                isHovered ? 'text-[var(--color-text-primary)] translate-x-0.5' : 'text-[var(--color-text-dim)]'
              )}
            />
          </div>
        </div>
      </div>
    </Link>
  );
}

function RiskPill({ score }: { score: number }) {
  const isHigh = score >= 75;
  const isWarn = score >= 40 && !isHigh;
  const isMed = score >= 20 && !isWarn && !isHigh;

  const color = isHigh ? 'var(--color-severity-critical)'
    : isWarn ? 'var(--color-severity-high)'
    : isMed ? 'var(--color-severity-medium)'
    : 'var(--color-severity-healthy)';

  return (
    <div
      className="flex items-center gap-2 px-2 py-0.5 rounded-md border bg-[var(--color-surface-2)] h-7"
      style={{ borderColor: `${color}30` }}
      title={`Risk Score: ${score}`}
    >
      <span className="text-[9px] uppercase tracking-wider text-[var(--color-text-dim)] font-semibold">Risk</span>
      <span
        className="text-[12px] font-bold tabular-nums"
        style={{ color }}
      >
        {score}
      </span>
    </div>
  );
}

function formatEmailTime(ts: string): string {
  const d = new Date(ts);
  const now = new Date();
  const isToday = d.toDateString() === now.toDateString();
  if (isToday) {
    return d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
  }
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}
