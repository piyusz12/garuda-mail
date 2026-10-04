'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Star as StarIcon, ChevronRight, Lock, LockOpen, AlertTriangle, RefreshCw } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import Link from 'next/link';
import type { EmailMessage } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

export default function StarredPage() {
  const [emails, setEmails] = useState<EmailMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStarred = useCallback(async (isSilent = false) => {
    if (!isSilent) setRefreshing(true);
    try {
      const res = await fetch('/api/emails?folder=starred');
      if (res.ok) {
        const data = await res.json();
        if (data.emails && Array.isArray(data.emails)) {
          const mapped: EmailMessage[] = data.emails.map((e: any) => ({
            id: e.id,
            folder: 'starred',
            from: {
              name: e.from?.name || 'Unknown',
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
            starred: true,
            attachments: e.attachments || [],
            security: {
              level: e.riskScore && e.riskScore > 50 ? 'critical' : e.tlsVersion ? 'secure' : 'warning',
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
        setEmails([]);
      }
    } catch {
      // keep current emails
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchStarred();
    const interval = setInterval(() => fetchStarred(true), 6000);
    return () => clearInterval(interval);
  }, [fetchStarred]);

  return (
    <AppShell title="Starred" description={`${emails.length} starred message${emails.length !== 1 ? 's' : ''}`}>
      <motion.div initial="initial" animate="animate" className="space-y-4">
        <div className="flex justify-end">
          <button
            onClick={() => fetchStarred(false)}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium rounded-md text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-[var(--color-border)] transition-colors"
          >
            <RefreshCw size={12} className={refreshing ? 'animate-spin text-[var(--color-accent)]' : ''} />
            <span>{refreshing ? 'Syncing...' : 'Sync'}</span>
          </button>
        </div>

        <motion.div {...fadeUp} className="card overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-20 text-[13px] text-[var(--color-text-muted)]">
              <RefreshCw size={18} className="animate-spin mr-2 text-[var(--color-accent)]" />
              Loading starred messages...
            </div>
          ) : emails.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <StarIcon size={40} className="text-[var(--color-text-dim)] mb-4" />
              <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">No starred messages</h3>
              <p className="text-[13px] text-[var(--color-text-muted)]">Star important emails for quick access.</p>
            </div>
          ) : (
            <div className="divide-y divide-[var(--color-border-subtle)]">
              {emails.map(email => (
                <StarredEmailRow key={email.id} email={email} />
              ))}
            </div>
          )}
        </motion.div>
      </motion.div>
    </AppShell>
  );
}

function StarredEmailRow({ email }: { email: EmailMessage }) {
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
      <StarIcon size={14} className="flex-shrink-0 text-[var(--color-severity-high)] fill-[var(--color-severity-high)]" />
      <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: securityColor }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[13px] font-semibold text-[var(--color-text-primary)] truncate">{email.from.name}</span>
          <span className="text-[10px] text-[var(--color-text-dim)] text-mono">{email.from.domain}</span>
        </div>
        <div className="text-[13px] font-medium text-[var(--color-text-secondary)] truncate mb-0.5">{email.subject}</div>
        <div className="text-[12px] text-[var(--color-text-muted)] truncate">{email.preview}</div>
      </div>
      <div className="flex-shrink-0 flex flex-col items-end gap-1.5">
        <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums">
          {new Date(email.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
        </span>
        <div className="flex items-center gap-1.5">
          {email.security.tlsVersion ? (
            <span className="text-[10px] font-medium text-mono px-1.5 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-text-secondary)]">
              <Lock size={9} className="inline mr-0.5" />{email.security.tlsVersion}
            </span>
          ) : (
            <span className="text-[10px] font-semibold text-[var(--color-severity-critical)] px-1.5 py-0.5 rounded bg-[var(--color-severity-critical-bg)]">
              <LockOpen size={9} className="inline mr-0.5" />NONE
            </span>
          )}
        </div>
      </div>
      <ChevronRight size={14} className="flex-shrink-0 text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors" />
    </Link>
  );
}
