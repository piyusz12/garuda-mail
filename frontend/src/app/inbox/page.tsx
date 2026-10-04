'use client';

import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Inbox as InboxIcon, Star, Paperclip, Shield, AlertTriangle,
  ChevronRight, Lock, LockOpen, Eye, Filter,
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { getEmailsByFolder } from '@/lib/mock/emails';
import Link from 'next/link';
import clsx from 'clsx';
import type { EmailMessage, SecurityLevel } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

export default function InboxPage() {
  const emails = getEmailsByFolder('inbox');
  const [securityFilter, setSecurityFilter] = useState<SecurityLevel | 'all'>('all');
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    if (securityFilter === 'all') return emails;
    return emails.filter(e => e.security.level === securityFilter);
  }, [emails, securityFilter]);

  const unreadCount = emails.filter(e => !e.read).length;
  const criticalCount = emails.filter(e => e.security.level === 'critical').length;

  return (
    <AppShell title="Inbox" description={`${emails.length} messages • ${unreadCount} unread • ${criticalCount} critical`}>
      <motion.div initial="initial" animate="animate" className="space-y-4">

        {/* Security Filter Bar */}
        <motion.div {...fadeUp} className="card p-3 flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-[var(--color-text-muted)]" />
            <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium">Security</span>
          </div>
          {[
            { id: 'all' as const, label: 'All', count: emails.length },
            { id: 'critical' as const, label: 'Critical', count: emails.filter(e => e.security.level === 'critical').length },
            { id: 'warning' as const, label: 'Warning', count: emails.filter(e => e.security.level === 'warning').length },
            { id: 'secure' as const, label: 'Secure', count: emails.filter(e => e.security.level === 'secure').length },
          ].map(f => (
            <button
              key={f.id}
              onClick={() => setSecurityFilter(f.id)}
              className={clsx(
                'px-3 py-1.5 text-[11px] font-medium rounded-md transition-colors',
                securityFilter === f.id
                  ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[rgba(56,189,248,0.15)]'
                  : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent'
              )}
            >
              {f.label}
              <span className="ml-1 tabular-nums opacity-60">{f.count}</span>
            </button>
          ))}
        </motion.div>

        {/* Email List */}
        <motion.div {...fadeUp} className="card overflow-hidden">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <InboxIcon size={40} className="text-[var(--color-text-dim)] mb-4" />
              <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">No messages match filter</h3>
              <p className="text-[13px] text-[var(--color-text-muted)]">Try adjusting your security filter.</p>
            </div>
          ) : (
            <div className="divide-y divide-[var(--color-border-subtle)]">
              {filtered.map((email, i) => (
                <EmailRow
                  key={email.id}
                  email={email}
                  index={i}
                  isHovered={hoveredId === email.id}
                  onHover={setHoveredId}
                />
              ))}
            </div>
          )}
        </motion.div>
      </motion.div>
    </AppShell>
  );
}

function EmailRow({ email, index, isHovered, onHover }: {
  email: EmailMessage; index: number; isHovered: boolean; onHover: (id: string | null) => void;
}) {
  const securityColor = {
    secure: 'var(--color-severity-healthy)',
    warning: 'var(--color-severity-high)',
    critical: 'var(--color-severity-critical)',
    unknown: 'var(--color-text-dim)',
  }[email.security.level];

  const securityBg = {
    secure: 'rgba(16, 185, 129, 0.04)',
    warning: 'rgba(245, 158, 11, 0.04)',
    critical: 'rgba(239, 68, 68, 0.06)',
    unknown: 'transparent',
  }[email.security.level];

  return (
    <Link
      href={`/inbox/${email.id}`}
      className={clsx(
        'flex items-center gap-4 px-4 py-3.5 transition-all duration-150 group',
        !email.read && 'bg-[rgba(56,189,248,0.02)]',
        isHovered && 'bg-[var(--color-surface-2)]',
      )}
      style={email.security.level === 'critical' && !isHovered ? { backgroundColor: securityBg } : undefined}
      onMouseEnter={() => onHover(email.id)}
      onMouseLeave={() => onHover(null)}
    >
      {/* Security Indicator */}
      <div className="flex-shrink-0 flex flex-col items-center gap-1.5">
        <div
          className="w-2 h-2 rounded-full flex-shrink-0"
          style={{ backgroundColor: securityColor, boxShadow: email.security.level === 'critical' ? `0 0 6px ${securityColor}40` : 'none' }}
          title={`Security: ${email.security.level}`}
        />
        {email.starred && (
          <Star size={12} className="text-[var(--color-severity-high)] fill-[var(--color-severity-high)]" />
        )}
      </div>

      {/* Sender & Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className={clsx(
            'text-[13px] truncate',
            !email.read ? 'font-semibold text-[var(--color-text-primary)]' : 'font-medium text-[var(--color-text-secondary)]'
          )}>
            {email.from.name}
          </span>
          <span className="text-[10px] text-[var(--color-text-dim)] text-mono">{email.from.domain}</span>
        </div>
        <div className="flex items-center gap-2 mb-0.5">
          <span className={clsx(
            'text-[13px] truncate',
            !email.read ? 'font-semibold text-[var(--color-text-primary)]' : 'text-[var(--color-text-secondary)]'
          )}>
            {email.subject}
          </span>
        </div>
        <div className="text-[12px] text-[var(--color-text-muted)] truncate">
          {email.preview}
        </div>
      </div>

      {/* Security Badge */}
      <div className="flex-shrink-0 flex flex-col items-end gap-1.5">
        <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums whitespace-nowrap">
          {formatEmailTime(email.timestamp)}
        </span>
        <div className="flex items-center gap-1.5">
          {email.attachments.length > 0 && (
            <Paperclip size={12} className="text-[var(--color-text-dim)]" />
          )}
          {email.security.findingsCount > 0 && (
            <span className="flex items-center gap-0.5 text-[10px] font-semibold px-1.5 py-0.5 rounded"
              style={{ color: securityColor, backgroundColor: `${securityColor}15` }}>
              <AlertTriangle size={10} />
              {email.security.findingsCount}
            </span>
          )}
          {email.security.tlsVersion ? (
            <span className="flex items-center gap-0.5 text-[10px] font-medium text-mono px-1.5 py-0.5 rounded bg-[var(--color-surface-3)]"
              style={{ color: email.security.tlsVersion === 'TLS 1.3' ? 'var(--color-severity-healthy)' : email.security.tlsVersion === 'TLS 1.2' ? 'var(--color-text-secondary)' : 'var(--color-severity-critical)' }}>
              <Lock size={9} />
              {email.security.tlsVersion}
            </span>
          ) : email.security.level !== 'unknown' ? (
            <span className="flex items-center gap-0.5 text-[10px] font-semibold text-[var(--color-severity-critical)] px-1.5 py-0.5 rounded bg-[var(--color-severity-critical-bg)]">
              <LockOpen size={9} />
              NONE
            </span>
          ) : null}
          {email.security.riskScore !== null && (
            <RiskPill score={email.security.riskScore} />
          )}
        </div>
      </div>

      {/* Open Arrow */}
      <ChevronRight
        size={14}
        className={clsx(
          'flex-shrink-0 transition-all duration-150',
          isHovered ? 'text-[var(--color-accent)] translate-x-0.5' : 'text-[var(--color-text-dim)]'
        )}
      />
    </Link>
  );
}

function RiskPill({ score }: { score: number }) {
  const color = score >= 75 ? 'var(--color-severity-critical)'
    : score >= 50 ? 'var(--color-severity-high)'
    : score >= 25 ? 'var(--color-severity-medium)'
    : 'var(--color-severity-healthy)';
  return (
    <span
      className="text-[10px] font-bold tabular-nums px-1.5 py-0.5 rounded"
      style={{ color, backgroundColor: `${color}15` }}
    >
      {score}
    </span>
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
