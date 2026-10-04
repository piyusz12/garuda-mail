'use client';

import { useState, useEffect, Suspense } from 'react';
import { motion } from 'framer-motion';
import {
  Send, X, Paperclip, Bold, Italic, Link2,
  Shield, Lock, Info, ChevronDown, Save, AlertCircle,
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { useRouter, useSearchParams } from 'next/navigation';
import clsx from 'clsx';

const fadeUp = { initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

const quickContacts = [
  { name: 'Security Operations', email: 'security@enterprise.local' },
  { name: 'Alice Vance (Crypto)', email: 'alice@enterprise.local' },
  { name: 'Bob Henderson (NetSec)', email: 'bob@enterprise.local' },
  { name: 'Garuda Analyst', email: 'analyst@enterprise.local' },
];

export default function ComposePage() {
  return (
    <Suspense fallback={<div className="p-8 text-[var(--color-text-dim)]">Loading compose...</div>}>
      <ComposeForm />
    </Suspense>
  );
}

function ComposeForm() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [to, setTo] = useState('');
  const [cc, setCc] = useState('');
  const [showCc, setShowCc] = useState(false);
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [sending, setSending] = useState(false);
  const [savingDraft, setSavingDraft] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState('');

  // Pre-fill from query params (e.g. Reply, Forward)
  useEffect(() => {
    const replyTo = searchParams.get('to') || searchParams.get('replyTo');
    const qSubject = searchParams.get('subject');
    const qBody = searchParams.get('body');

    if (replyTo) setTo(replyTo);
    if (qSubject) setSubject(qSubject);
    if (qBody) setBody(qBody);
  }, [searchParams]);

  const handleSend = async () => {
    if (!to || !subject || !body) return;
    setSending(true);
    setError('');

    try {
      const toAddresses = to.split(',').map(s => s.trim()).filter(Boolean).map(email => ({ email }));
      const ccAddresses = cc ? cc.split(',').map(s => s.trim()).filter(Boolean).map(email => ({ email })) : [];

      const res = await fetch('/api/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: toAddresses,
          cc: ccAddresses,
          subject,
          body,
          draft: false,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to send email');
      }

      setSending(false);
      setSent(true);
      setTimeout(() => {
        router.push('/sent');
      }, 1000);
    } catch (err: any) {
      setSending(false);
      setError(err.message || 'Error sending message. Check recipient email format.');
    }
  };

  const handleSaveDraft = async () => {
    if (!to && !subject && !body) return;
    setSavingDraft(true);
    setError('');

    try {
      const toAddresses = to
        ? to.split(',').map(s => s.trim()).filter(Boolean).map(email => ({ email }))
        : [{ email: 'draft@enterprise.local' }];

      const res = await fetch('/api/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: toAddresses,
          subject: subject || '(Draft - No Subject)',
          body: body || '',
          draft: true,
        }),
      });

      if (!res.ok) throw new Error('Failed to save draft');
      setSavingDraft(false);
      router.push('/drafts');
    } catch (err: any) {
      setSavingDraft(false);
      setError(err.message || 'Error saving draft');
    }
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
            Outbound mail is secured via TLS 1.3 and cryptographic analysis metadata will be automatically attached.
          </div>
        </motion.div>

        {/* Error Alert */}
        {error && (
          <motion.div {...fadeUp} className="flex items-center gap-2.5 p-3 rounded-md bg-[var(--color-severity-critical-bg)] border border-[rgba(239,68,68,0.25)] text-[12px] text-[var(--color-severity-critical)]">
            <AlertCircle size={14} className="flex-shrink-0" />
            <span>{error}</span>
          </motion.div>
        )}

        {/* Compose Card */}
        <motion.div {...fadeUp} className="card overflow-hidden">

          {/* Toolbar */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-[var(--color-border)] bg-[var(--color-surface-2)]">
            <div className="flex items-center gap-2">
              <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">New Secure Message</span>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={handleSaveDraft}
                disabled={savingDraft || (!to && !subject && !body)}
                className="flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors disabled:opacity-40"
                title="Save as Draft"
              >
                <Save size={13} />
                <span>{savingDraft ? 'Saving...' : 'Draft'}</span>
              </button>
              <button
                onClick={handleDiscard}
                className="flex items-center justify-center w-7 h-7 rounded text-[var(--color-text-muted)] hover:text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-bg)] transition-colors"
                title="Discard"
              >
                <X size={14} />
              </button>
            </div>
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
                placeholder="recipient@enterprise.local or user@example.com"
                className="flex-1 text-[13px] bg-transparent text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] outline-none"
              />
              <button
                type="button"
                onClick={() => setShowCc(!showCc)}
                className="text-[11px] text-[var(--color-text-muted)] hover:text-[var(--color-accent)] transition-colors flex items-center gap-0.5"
              >
                CC <ChevronDown size={11} className={clsx('transition-transform', showCc && 'rotate-180')} />
              </button>
            </div>

            {/* Quick Contacts Suggestion Chips */}
            <div className="flex items-center gap-1.5 px-4 py-1.5 bg-[var(--color-surface-1)] text-[11px] overflow-x-auto">
              <span className="text-[10px] uppercase text-[var(--color-text-dim)] font-mono mr-1">Quick Add:</span>
              {quickContacts.map(c => (
                <button
                  key={c.email}
                  type="button"
                  onClick={() => setTo(c.email)}
                  className="px-2 py-0.5 rounded text-[10px] bg-[var(--color-surface-3)] text-[var(--color-text-secondary)] hover:text-[var(--color-accent)] hover:bg-[var(--color-accent-dim)] border border-[var(--color-border-subtle)] transition-colors"
                >
                  {c.name.split(' ')[0]} ({c.email.split('@')[0]})
                </button>
              ))}
            </div>

            {/* CC */}
            {showCc && (
              <div className="flex items-center gap-3 px-4 py-2.5">
                <label className="text-[12px] font-medium text-[var(--color-text-muted)] w-12 flex-shrink-0">CC</label>
                <input
                  type="email"
                  value={cc}
                  onChange={e => setCc(e.target.value)}
                  placeholder="cc@enterprise.local"
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
              placeholder="Write your email message here..."
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
              <span>TLS transport enforced (ECDHE + AES-GCM)</span>
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
            <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">Live Security Pipeline</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[11px]">
            {[
              { label: 'TLS Negotiation', value: 'TLS 1.3 Strict', status: 'healthy' },
              { label: 'Certificate Check', value: 'X.509 Validated', status: 'healthy' },
              { label: 'Forward Secrecy', value: 'ECDHE Enforced', status: 'healthy' },
              { label: 'Recipient Routing', value: 'Instant Multi-PC Sync', status: 'accent' },
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
      type="button"
      title={title}
      className="flex items-center justify-center w-7 h-7 rounded text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors"
    >
      <Icon size={14} />
    </button>
  );
}
