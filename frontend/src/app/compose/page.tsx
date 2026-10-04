'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Send, X, Paperclip, Bold, Italic, Link2,
  Shield, Lock, Info, ChevronDown,
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { useRouter } from 'next/navigation';
import clsx from 'clsx';

const fadeUp = { initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function ComposePage() {
  const router = useRouter();
  const [to, setTo] = useState('');
  const [cc, setCc] = useState('');
  const [showCc, setShowCc] = useState(false);
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);

  const handleSend = async () => {
    if (!to || !subject || !body) return;
    setSending(true);
    await new Promise(r => setTimeout(r, 1200));
    setSending(false);
    setSent(true);
    await new Promise(r => setTimeout(r, 1500));
    router.push('/sent');
  };

  const handleDiscard = () => router.push('/inbox');

  return (
    <AppShell title="New Message" description="Compose a new secure email">
      <motion.div initial="initial" animate="animate" className="space-y-4 max-w-3xl">

        {/* Security Notice */}
        <motion.div {...fadeUp} className="flex items-start gap-3 p-3 rounded-lg border border-[rgba(56,189,248,0.15)] bg-[var(--color-accent-dim)]">
          <Shield size={14} className="text-[var(--color-accent)] mt-0.5 flex-shrink-0" />
          <div className="text-[12px] text-[var(--color-text-secondary)] leading-relaxed">
            <span className="font-semibold text-[var(--color-accent)]">Transport Security: </span>
            Outbound mail will be analyzed for TLS negotiation, certificate validity, and cryptographic compliance. Results will appear in the Sent folder.
          </div>
        </motion.div>

        {/* Compose Card */}
        <motion.div {...fadeUp} className="card overflow-hidden">

          {/* Toolbar */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-[var(--color-border)] bg-[var(--color-surface-2)]">
            <div className="flex items-center gap-1">
              <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">New Message</span>
            </div>
            <button
              onClick={handleDiscard}
              className="flex items-center justify-center w-6 h-6 rounded text-[var(--color-text-muted)] hover:text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-bg)] transition-colors"
              title="Discard"
            >
              <X size={14} />
            </button>
          </div>

          {/* Fields */}
          <div className="divide-y divide-[var(--color-border-subtle)]">
            {/* To */}
            <div className="flex items-center gap-3 px-4 py-2.5">
              <label className="text-[12px] font-medium text-[var(--color-text-muted)] w-12 flex-shrink-0">To</label>
              <input
                type="email"
                value={to}
                onChange={e => setTo(e.target.value)}
                placeholder="recipient@example.com"
                className="flex-1 text-[13px] bg-transparent text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] outline-none"
              />
              <button
                onClick={() => setShowCc(!showCc)}
                className="text-[11px] text-[var(--color-text-muted)] hover:text-[var(--color-accent)] transition-colors flex items-center gap-0.5"
              >
                CC <ChevronDown size={11} className={clsx('transition-transform', showCc && 'rotate-180')} />
              </button>
            </div>

            {/* CC */}
            {showCc && (
              <div className="flex items-center gap-3 px-4 py-2.5">
                <label className="text-[12px] font-medium text-[var(--color-text-muted)] w-12 flex-shrink-0">CC</label>
                <input
                  type="email"
                  value={cc}
                  onChange={e => setCc(e.target.value)}
                  placeholder="cc@example.com"
                  className="flex-1 text-[13px] bg-transparent text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] outline-none"
                />
              </div>
            )}

            {/* Subject */}
            <div className="flex items-center gap-3 px-4 py-2.5">
              <label className="text-[12px] font-medium text-[var(--color-text-muted)] w-12 flex-shrink-0">Subject</label>
              <input
                type="text"
                value={subject}
                onChange={e => setSubject(e.target.value)}
                placeholder="Message subject"
                className="flex-1 text-[13px] bg-transparent text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] outline-none font-medium"
              />
            </div>
          </div>

          {/* Body */}
          <div className="px-4 pt-2 pb-4">
            <textarea
              value={body}
              onChange={e => setBody(e.target.value)}
              placeholder="Write your message here..."
              rows={14}
              className="w-full text-[13px] leading-relaxed bg-transparent text-[var(--color-text-secondary)] placeholder:text-[var(--color-text-dim)] outline-none resize-none"
            />
          </div>

          {/* Format Toolbar */}
          <div className="flex items-center gap-1 px-3 py-2 border-t border-[var(--color-border-subtle)] bg-[var(--color-surface-2)]">
            <FormatButton icon={Bold} title="Bold" />
            <FormatButton icon={Italic} title="Italic" />
            <FormatButton icon={Link2} title="Link" />
            <div className="w-px h-4 bg-[var(--color-border)] mx-1" />
            <FormatButton icon={Paperclip} title="Attach file" />
          </div>

          {/* Send Bar */}
          <div className="flex items-center justify-between px-4 py-3 border-t border-[var(--color-border)] bg-[var(--color-surface-2)]">
            <div className="flex items-center gap-2 text-[11px] text-[var(--color-text-muted)]">
              <Lock size={11} className="text-[var(--color-accent)]" />
              <span>TLS transport will be enforced</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleDiscard}
                className="px-4 py-1.5 text-[12px] font-medium text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] rounded-md transition-colors border border-[var(--color-border)]"
              >
                Discard
              </button>
              <button
                onClick={handleSend}
                disabled={!to || !subject || !body || sending || sent}
                className={clsx(
                  'flex items-center gap-1.5 px-4 py-1.5 text-[12px] font-semibold rounded-md transition-all duration-200',
                  sent
                    ? 'bg-[var(--color-severity-healthy)] text-white'
                    : 'bg-[var(--color-accent)] text-[#0B0D10] hover:bg-[#5ccbfc] disabled:opacity-40 disabled:pointer-events-none'
                )}
              >
                {sending ? (
                  <>
                    <div className="w-3 h-3 border-2 border-[#0B0D10]/30 border-t-[#0B0D10] rounded-full animate-spin" />
                    Sending...
                  </>
                ) : sent ? (
                  <>✓ Sent</>
                ) : (
                  <>
                    <Send size={13} />
                    Send
                  </>
                )}
              </button>
            </div>
          </div>
        </motion.div>

        {/* Security Analysis Preview */}
        <motion.div {...fadeUp} className="card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Info size={13} className="text-[var(--color-accent)]" />
            <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">Post-Send Security Analysis</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[11px]">
            {[
              { label: 'TLS Negotiation', value: 'Will be captured', status: 'accent' },
              { label: 'Certificate Check', value: 'On delivery', status: 'accent' },
              { label: 'Forward Secrecy', value: 'Verified', status: 'healthy' },
              { label: 'JA4 Fingerprint', value: 'Recorded', status: 'accent' },
            ].map(item => (
              <div key={item.label} className="p-2.5 bg-[var(--color-surface-2)] rounded-md border border-[var(--color-border-subtle)]">
                <div className="text-[10px] text-[var(--color-text-dim)] mb-1">{item.label}</div>
                <div className={clsx(
                  'font-medium',
                  item.status === 'healthy' ? 'text-[var(--color-severity-healthy)]' : 'text-[var(--color-accent)]'
                )}>{item.value}</div>
              </div>
            ))}
          </div>
        </motion.div>

      </motion.div>
    </AppShell>
  );
}

function FormatButton({ icon: Icon, title }: { icon: React.ElementType; title: string }) {
  return (
    <button
      title={title}
      className="flex items-center justify-center w-7 h-7 rounded text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors"
    >
      <Icon size={14} />
    </button>
  );
}
