'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Trash2, RefreshCw, RotateCcw, AlertTriangle } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import type { EmailMessage } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 8 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.25 } };

export default function TrashPage() {
  const [emails, setEmails] = useState<EmailMessage[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchTrash = useCallback(async () => {
    try {
      const res = await fetch('/api/emails?folder=trash');
      if (res.ok) {
        const data = await res.json();
        if (data.emails && Array.isArray(data.emails)) {
          const mapped: EmailMessage[] = data.emails.map((e: any) => ({
            id: e.id,
            folder: 'trash',
            from: {
              name: e.from?.name || 'Unknown',
              email: e.from?.email || '',
              domain: '',
            },
            to: [],
            subject: e.subject || '(No Subject)',
            preview: e.preview || e.body?.slice(0, 100) || '',
            body: e.body || '',
            timestamp: e.sentAt || e.createdAt,
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
          setEmails(mapped);
        }
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTrash();
  }, [fetchTrash]);

  const handleRestore = async (id: string) => {
    setEmails(prev => prev.filter(e => e.id !== id));
    try {
      await fetch(`/api/emails/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folder: 'inbox' }),
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handlePermanentDelete = async (id: string) => {
    setEmails(prev => prev.filter(e => e.id !== id));
    try {
      await fetch(`/api/emails/${id}?permanent=true`, {
        method: 'DELETE',
      });
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <AppShell title="Trash" description={`${emails.length} deleted messages`}>
      <motion.div initial="initial" animate="animate" className="space-y-4">
        <motion.div {...fadeUp} className="card overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-20 text-[13px] text-[var(--color-text-muted)]">
              <RefreshCw size={18} className="animate-spin mr-2 text-[var(--color-accent)]" />
              Loading trash...
            </div>
          ) : emails.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Trash2 size={40} className="text-[var(--color-text-dim)] mb-4" />
              <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">Trash is empty</h3>
              <p className="text-[13px] text-[var(--color-text-muted)]">Deleted messages will appear here.</p>
            </div>
          ) : (
            <div className="divide-y divide-[var(--color-border-subtle)]">
              {emails.map(email => (
                <div
                  key={email.id}
                  className="flex items-center justify-between gap-4 px-4 py-3.5 hover:bg-[var(--color-surface-2)] transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[13px] font-medium text-[var(--color-text-secondary)]">{email.from.name}</span>
                    </div>
                    <div className="text-[13px] font-medium text-[var(--color-text-primary)] truncate mb-0.5">{email.subject}</div>
                    <div className="text-[12px] text-[var(--color-text-muted)] truncate">{email.preview}</div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <button
                      onClick={() => handleRestore(email.id)}
                      className="flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium rounded text-[var(--color-accent)] hover:bg-[var(--color-accent-dim)] transition-colors border border-[rgba(56,189,248,0.2)]"
                    >
                      <RotateCcw size={12} />
                      Restore
                    </button>
                    <button
                      onClick={() => handlePermanentDelete(email.id)}
                      className="flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium rounded text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-bg)] transition-colors border border-[rgba(239,68,68,0.2)]"
                    >
                      <Trash2 size={12} />
                      Delete Permanently
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      </motion.div>
    </AppShell>
  );
}
