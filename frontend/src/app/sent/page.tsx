'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Send as SendIcon, Lock, LockOpen, Paperclip,
  ChevronRight, Shield,
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { getEmailsByFolder } from '@/lib/mock/emails';
import Link from 'next/link';
import clsx from 'clsx';
import type { EmailMessage } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

export default function SentPage() {
  const emails = getEmailsByFolder('sent');

  return (
    <AppShell title="Sent" description={`${emails.length} sent messages`}>
      <motion.div initial="initial" animate="animate" className="space-y-4">
        <motion.div {...fadeUp} className="card overflow-hidden">
          {emails.length === 0 ? (
            <EmptyFolder icon={SendIcon} label="No sent messages" />
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
      <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: securityColor }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[12px] text-[var(--color-text-muted)]">To:</span>
          <span className="text-[13px] font-medium text-[var(--color-text-secondary)] truncate">
            {email.to.map(t => t.name).join(', ')}
          </span>
        </div>
        <div className="text-[13px] font-medium text-[var(--color-text-primary)] truncate mb-0.5">{email.subject}</div>
        <div className="text-[12px] text-[var(--color-text-muted)] truncate">{email.preview}</div>
      </div>
      <div className="flex-shrink-0 flex flex-col items-end gap-1.5">
        <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums">{formatEmailTime(email.timestamp)}</span>
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
