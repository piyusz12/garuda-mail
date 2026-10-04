'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { FileEdit, ChevronRight, Clock, RefreshCw } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { getEmailsByFolder } from '@/lib/mock/emails';
import Link from 'next/link';
import type { EmailMessage } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

export default function DraftsPage() {
  const [drafts, setDrafts] = useState<EmailMessage[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchDrafts = useCallback(async () => {
    try {
      const res = await fetch('/api/emails?folder=drafts');
      if (res.ok) {
        const data = await res.json();
        if (data.emails && Array.isArray(data.emails)) {
          const mapped: EmailMessage[] = data.emails.map((e: any) => ({
            id: e.id,
            folder: 'drafts',
            from: { name: 'Me', email: '', domain: '' },
            to: e.recipients?.map((r: any) => ({
              name: r.name || r.address,
              email: r.address || '',
              domain: '',
            })) || [],
            subject: e.subject || '(No Subject)',
            preview: e.preview || e.body?.slice(0, 100) || '',
            body: e.body || '',
            timestamp: e.updatedAt || e.createdAt,
            read: true,
            starred: false,
            attachments: [],
            security: {
              level: 'unknown',
              tlsVersion: null,
              cipher: null,
              forwardSecrecy: null,
              starttls: null,
              certificateStatus: null,
              riskScore: null,
              anomalyScore: null,
              findingsCount: 0,
              sessionId: null,
            },
            threadId: e.threadId || `THREAD-${e.id}`,
            labels: [],
          }));
          setDrafts(mapped);
        }
      } else {
        setDrafts(getEmailsByFolder('drafts'));
      }
    } catch {
      setDrafts(getEmailsByFolder('drafts'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDrafts();
  }, [fetchDrafts]);

  return (
    <AppShell title="Drafts" description={`${drafts.length} draft${drafts.length !== 1 ? 's' : ''}`}>
      <motion.div initial="initial" animate="animate" className="space-y-4">
        <motion.div {...fadeUp} className="card overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-20 text-[13px] text-[var(--color-text-muted)]">
              <RefreshCw size={18} className="animate-spin mr-2 text-[var(--color-accent)]" />
              Loading drafts...
            </div>
          ) : drafts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <FileEdit size={40} className="text-[var(--color-text-dim)] mb-4" />
              <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">No drafts</h3>
              <p className="text-[13px] text-[var(--color-text-muted)]">Start composing to save drafts.</p>
              <Link
                href="/compose"
                className="mt-4 px-3 py-1.5 rounded-md text-[12px] font-semibold bg-[var(--color-accent)] text-[#0B0D10]"
              >
                Compose Message
              </Link>
            </div>
          ) : (
            <div className="divide-y divide-[var(--color-border-subtle)]">
              {drafts.map(email => (
                <Link
                  key={email.id}
                  href={`/compose?to=${encodeURIComponent(email.to[0]?.email || '')}&subject=${encodeURIComponent(email.subject)}&body=${encodeURIComponent(email.body)}`}
                  className="flex items-center gap-4 px-4 py-3.5 hover:bg-[var(--color-surface-2)] transition-colors group"
                >
                  <FileEdit size={16} className="flex-shrink-0 text-[var(--color-text-muted)]" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[12px] text-[var(--color-text-muted)]">To:</span>
                      <span className="text-[13px] font-medium text-[var(--color-text-secondary)] truncate">
                        {email.to.map(t => t.name || t.email).join(', ') || 'No recipient specified'}
                      </span>
                    </div>
                    <div className="text-[13px] font-semibold text-[var(--color-severity-high)] truncate mb-0.5">
                      [Draft] {email.subject}
                    </div>
                    <div className="text-[12px] text-[var(--color-text-muted)] truncate">{email.preview}</div>
                  </div>
                  <div className="flex items-center gap-1 text-[11px] text-[var(--color-text-dim)]">
                    <Clock size={11} />
                    {new Date(email.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                  </div>
                  <ChevronRight size={14} className="flex-shrink-0 text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors" />
                </Link>
              ))}
            </div>
          )}
        </motion.div>
      </motion.div>
    </AppShell>
  );
}
