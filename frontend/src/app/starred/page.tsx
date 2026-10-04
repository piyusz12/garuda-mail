'use client';

import { motion } from 'framer-motion';
import { Star as StarIcon, ChevronRight, Lock, LockOpen, AlertTriangle } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { getEmailsByFolder } from '@/lib/mock/emails';
import Link from 'next/link';
import type { EmailMessage } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

export default function StarredPage() {
  const emails = getEmailsByFolder('starred');

  return (
    <AppShell title="Starred" description={`${emails.length} starred message${emails.length !== 1 ? 's' : ''}`}>
      <motion.div initial="initial" animate="animate" className="space-y-4">
        <motion.div {...fadeUp} className="card overflow-hidden">
          {emails.length === 0 ? (
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
          <span className="text-[10px] text-[var(--color-text-dim)] capitalize">{email.folder}</span>
        </div>
        <div className="text-[13px] font-medium text-[var(--color-text-secondary)] truncate mb-0.5">{email.subject}</div>
        <div className="text-[12px] text-[var(--color-text-muted)] truncate">{email.preview}</div>
      </div>
      <div className="flex-shrink-0 flex flex-col items-end gap-1.5">
        <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums">
          {new Date(email.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
        </span>
        <div className="flex items-center gap-1.5">
          {email.security.findingsCount > 0 && (
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded"
              style={{ color: securityColor, backgroundColor: `${securityColor}15` }}>
              <AlertTriangle size={9} className="inline mr-0.5" />{email.security.findingsCount}
            </span>
          )}
          {email.security.tlsVersion ? (
            <span className="text-[10px] font-medium text-mono px-1.5 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-text-secondary)]">
              <Lock size={9} className="inline mr-0.5" />{email.security.tlsVersion}
            </span>
          ) : email.security.level !== 'unknown' ? (
            <span className="text-[10px] font-semibold text-[var(--color-severity-critical)] px-1.5 py-0.5 rounded bg-[var(--color-severity-critical-bg)]">
              <LockOpen size={9} className="inline mr-0.5" />NONE
            </span>
          ) : null}
        </div>
      </div>
      <ChevronRight size={14} className="flex-shrink-0 text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors" />
    </Link>
  );
}
