'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Send as SendIcon, Lock, LockOpen, Paperclip,
  ChevronRight, RefreshCw, Network,
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { getEmailsByFolder } from '@/lib/mock/emails';
import Link from 'next/link';
import clsx from 'clsx';
import type { EmailMessage } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

export default function SentPage() {
  const [emails, setEmails] = useState<EmailMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchSent = useCallback(async (isSilent = false) => {
    if (!isSilent) setRefreshing(true);
    try {
      const res = await fetch('/api/emails?folder=sent');
      if (res.ok) {
        const data = await res.json();
        if (data.emails && Array.isArray(data.emails)) {
          const mapped: EmailMessage[] = data.emails.map((e: any) => ({
            id: e.id,
            folder: 'sent',
            from: {
              name: e.from?.name || 'Me',
              email: e.from?.email || '',
              domain: (e.from?.email || '').split('@')[1] || '',
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
            read: true,
            starred: e.starred || false,
            attachments: e.attachments || [],
            security: {
              level: e.tlsVersion ? 'secure' : 'critical',
              tlsVersion: e.tlsVersion || null,
              cipher: e.cipher || null,
              forwardSecrecy: e.forwardSecrecy ?? null,
              starttls: e.starttls ?? null,
              certificateStatus: 'valid',
              riskScore: e.riskScore ?? 0,
              anomalyScore: null,
              findingsCount: 0,
              sessionId: null,
            },
            threadId: e.threadId || `THREAD-${e.id}`,
            labels: [],
          }));
          setEmails(mapped);
        }
      } else {
        setEmails(getEmailsByFolder('sent'));
      }
    } catch {
      setEmails(getEmailsByFolder('sent'));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchSent();
    const interval = setInterval(() => fetchSent(true), 6000);
    return () => clearInterval(interval);
  }, [fetchSent]);

  return (
    <AppShell title="Sent" description={`${emails.length} sent messages • Multi-PC sync active`}>
      <motion.div initial="initial" animate="animate" className="space-y-4">
        <div className="flex justify-end">
          <button
            onClick={() => fetchSent(false)}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium rounded-md text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-[var(--color-border)] transition-colors"
          >
            <RefreshCw size={12} className={clsx(refreshing && 'animate-spin text-[var(--color-accent)]')} />
            <span>{refreshing ? 'Syncing...' : 'Sync'}</span>
          </button>
        </div>

        <motion.div {...fadeUp} className="card overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-20 text-[13px] text-[var(--color-text-muted)]">
              <RefreshCw size={18} className="animate-spin mr-2 text-[var(--color-accent)]" />
              Loading sent messages...
            </div>
          ) : emails.length === 0 ? (
            <EmptyFolder icon={SendIcon} label="No sent messages yet" />
          ) : (
            <div className="divide-y divide-[var(--color-border-subtle)]">
              {emails.map(email => (
                <SentEmailRow key={email.id} email={email} />
              ))}
            </div>
          )}
        </motion.div>
      </motion.div>
    </AppShell>
  );
}

function SentEmailRow({ email }: { email: EmailMessage }) {
  const securityColor = {
    secure: 'var(--color-severity-healthy)',
    warning: 'var(--color-severity-high)',
    critical: 'var(--color-severity-critical)',
    unknown: 'var(--color-text-dim)',
  }[email.security.level];

  return (
    <Link
      href={`/inbox/${email.id}`}
      className="flex items-center gap-4 px-4 py-3.5 hover:bg-[var(--color-surface-2)] transition-colors group"
    >
      <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: securityColor }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[12px] text-[var(--color-text-muted)]">To:</span>
          <span className="text-[13px] font-medium text-[var(--color-text-secondary)] truncate">
            {email.to.map(t => t.name || t.email).join(', ') || 'Unknown Recipient'}
          </span>
        </div>
        <div className="text-[13px] font-medium text-[var(--color-text-primary)] truncate mb-0.5">{email.subject}</div>
        <div className="text-[12px] text-[var(--color-text-muted)] truncate">{email.preview}</div>
      </div>
      <div className="flex-shrink-0 flex flex-col items-end gap-1.5">
        <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums">{formatEmailTime(email.timestamp)}</span>
        <div className="flex items-center gap-1.5">
          {email.attachments.length > 0 && (
            <Paperclip size={12} className="text-[var(--color-text-dim)]" />
          )}
          {email.security.tlsVersion ? (
            <span className="text-[10px] font-medium text-mono px-1.5 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-text-secondary)]">
              <Lock size={9} className="inline mr-0.5" />{email.security.tlsVersion}
            </span>
          ) : (
            <span className="text-[10px] font-semibold text-[var(--color-severity-critical)] px-1.5 py-0.5 rounded bg-[var(--color-severity-critical-bg)]">
              <LockOpen size={9} className="inline mr-0.5" />NONE
            </span>
          )}
          {email.security.cipher?.includes('[') && (
            <span className="flex items-center gap-1 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[rgba(56,189,248,0.2)]">
              <Network size={9} />
              {email.security.cipher.match(/\[([A-Z0-9\/\-]+)\]/)?.[1] || 'SMTP'}
            </span>
          )}
        </div>
      </div>
      <ChevronRight size={14} className="flex-shrink-0 text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors" />
    </Link>
  );
}

function EmptyFolder({ icon: Icon, label }: { icon: React.ElementType; label: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <Icon size={40} className="text-[var(--color-text-dim)] mb-4" />
      <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">{label}</h3>
    </div>
  );
}

function formatEmailTime(ts: string): string {
  const d = new Date(ts);
  const now = new Date();
  const isToday = d.toDateString() === now.toDateString();
  if (isToday) return d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}
