'use client';

import { use, useState } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Star, Paperclip, Reply, Forward, Trash2,
  Shield, AlertTriangle, Lock, LockOpen, Award, Brain,
  ExternalLink, CheckCircle, XCircle, AlertCircle, ChevronRight,
  Network, Eye,
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { getEmailById } from '@/lib/mock/emails';
import { mockFindings, mockSessions } from '@/lib/mock/data';
import Link from 'next/link';
import clsx from 'clsx';
import type { EmailMessage } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.28 } };

export default function EmailDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const email = getEmailById(id);
  const [securityExpanded, setSecurityExpanded] = useState(true);

  if (!email) {
    return (
      <AppShell title="Email Not Found">
        <div className="flex flex-col items-center justify-center py-20">
          <Shield size={48} className="text-[var(--color-text-dim)] mb-4" />
          <h2 className="text-lg font-semibold mb-2">Email not found</h2>
          <Link href="/inbox" className="text-[13px] text-[var(--color-accent)] hover:underline">← Back to Inbox</Link>
        </div>
      </AppShell>
    );
  }

  const session = email.security.sessionId
    ? mockSessions.find(s => s.id === email.security.sessionId)
    : null;

  const findings = email.security.sessionId
    ? mockFindings.filter(f => f.relatedSessionIds.includes(email.security.sessionId!))
    : [];

  return (
    <AppShell title={email.subject} description={`From ${email.from.email} • ${formatDateTime(email.timestamp)}`}>
      <motion.div initial="initial" animate="animate" className="space-y-4 max-w-4xl">

        {/* Back nav */}
        <motion.div {...fadeUp}>
          <Link href="/inbox" className="inline-flex items-center gap-1.5 text-[12px] text-[var(--color-text-muted)] hover:text-[var(--color-accent)] transition-colors">
            <ArrowLeft size={14} /> Back to Inbox
          </Link>
        </motion.div>

        {/* Email Header */}
        <motion.div {...fadeUp} className="card p-5">
          <div className="flex items-start justify-between gap-4 mb-4">
            <div className="flex-1 min-w-0">
              <h1 className="text-[18px] font-bold text-[var(--color-text-primary)] leading-tight mb-2">
                {email.subject}
              </h1>
              <div className="flex items-center gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-full bg-[var(--color-surface-3)] border border-[var(--color-border)] flex items-center justify-center text-[12px] font-bold text-[var(--color-text-secondary)]">
                    {email.from.name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-[13px] font-semibold text-[var(--color-text-primary)]">{email.from.name}</div>
                    <div className="text-[11px] text-[var(--color-text-muted)] text-mono">{email.from.email}</div>
                  </div>
                </div>
                <span className="text-[11px] text-[var(--color-text-dim)]">
                  To: {email.to.map(t => t.name).join(', ')}
                </span>
                <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums ml-auto">
                  {formatDateTime(email.timestamp)}
                </span>
              </div>
            </div>
          </div>

          {/* Email Actions */}
          <div className="flex items-center gap-2 pt-4 border-t border-[var(--color-border-subtle)]">
            <button className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] rounded-md transition-colors border border-[var(--color-border)]">
              <Reply size={13} /> Reply
            </button>
            <button className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] rounded-md transition-colors border border-[var(--color-border)]">
              <Forward size={13} /> Forward
            </button>
            <button className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-severity-high)] hover:bg-[rgba(245,158,11,0.08)] rounded-md transition-colors border border-[var(--color-border)] ml-auto">
              <Star size={13} className={email.starred ? 'text-[var(--color-severity-high)] fill-[var(--color-severity-high)]' : ''} />
              {email.starred ? 'Unstar' : 'Star'}
            </button>
            <button className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-bg)] rounded-md transition-colors border border-[var(--color-border)]">
              <Trash2 size={13} /> Delete
            </button>
          </div>
        </motion.div>

        {/* Security Analysis Header — THE FORENSIC OVERLAY */}
        <motion.div {...fadeUp}>
          <SecurityHeader
            email={email}
            session={session}
            findings={findings}
            expanded={securityExpanded}
            onToggle={() => setSecurityExpanded(e => !e)}
          />
        </motion.div>

        {/* Email Body */}
        <motion.div {...fadeUp} className="card p-6">
          <pre className="text-[13px] text-[var(--color-text-secondary)] leading-relaxed whitespace-pre-wrap font-sans">
            {email.body}
          </pre>

          {/* Attachments */}
          {email.attachments.length > 0 && (
            <div className="mt-5 pt-5 border-t border-[var(--color-border-subtle)]">
              <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold mb-3 flex items-center gap-1.5">
                <Paperclip size={12} />
                Attachments ({email.attachments.length})
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {email.attachments.map((att, i) => (
                  <div key={i} className="flex items-center gap-3 p-3 rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border)] hover:border-[var(--color-border-active)] transition-colors cursor-pointer">
                    <div className="w-8 h-8 rounded bg-[var(--color-surface-3)] flex items-center justify-center">
                      <Paperclip size={14} className="text-[var(--color-text-muted)]" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-[12px] font-medium text-[var(--color-text-primary)] truncate">{att.name}</div>
                      <div className="text-[10px] text-[var(--color-text-dim)]">{formatBytes(att.size)}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </motion.div>

        {/* Forensic Findings linked to this email */}
        {findings.length > 0 && (
          <motion.div {...fadeUp} className="card p-5">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle size={14} className="text-[var(--color-severity-critical)]" />
              <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">
                Security Findings for this Message
              </span>
              <span className="text-[10px] tabular-nums bg-[var(--color-severity-critical-bg)] text-[var(--color-severity-critical)] px-1.5 py-0.5 rounded font-semibold">
                {findings.length}
              </span>
            </div>
            <div className="space-y-2">
              {findings.map(f => (
                <Link
                  key={f.id}
                  href={`/findings/${f.id}`}
                  className="flex items-center justify-between p-3 rounded-md bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] transition-colors group border border-[var(--color-border-subtle)] hover:border-[var(--color-border-active)]"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <SeverityBadge severity={f.severity} size="xs" />
                    <div className="min-w-0">
                      <div className="text-[13px] font-medium text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] transition-colors truncate">
                        {f.title}
                      </div>
                      <div className="text-[11px] text-[var(--color-text-dim)]">
                        {f.id} • {f.category} • Confidence {f.confidence}%
                      </div>
                    </div>
                  </div>
                  <ChevronRight size={14} className="flex-shrink-0 text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)]" />
                </Link>
              ))}
            </div>
          </motion.div>
        )}

      </motion.div>
    </AppShell>
  );
}

/* ── Security Header (The Forensic Overlay) ── */
function SecurityHeader({ email, session, findings, expanded, onToggle }: {
  email: EmailMessage;
  session: any;
  findings: any[];
  expanded: boolean;
  onToggle: () => void;
}) {
  const s = email.security;

  const levelColor = {
    secure: 'var(--color-severity-healthy)',
    warning: 'var(--color-severity-high)',
    critical: 'var(--color-severity-critical)',
    unknown: 'var(--color-text-dim)',
  }[s.level];

  const levelBg = {
    secure: 'rgba(16, 185, 129, 0.06)',
    warning: 'rgba(245, 158, 11, 0.06)',
    critical: 'rgba(239, 68, 68, 0.08)',
    unknown: 'transparent',
  }[s.level];

  const levelIcon = {
    secure: <CheckCircle size={16} style={{ color: levelColor }} />,
    warning: <AlertCircle size={16} style={{ color: levelColor }} />,
    critical: <XCircle size={16} style={{ color: levelColor }} />,
    unknown: <Shield size={16} style={{ color: levelColor }} />,
  }[s.level];

  const levelLabel = {
    secure: 'Secure',
    warning: 'Security Warning',
    critical: 'Critical Risk',
    unknown: 'Unknown',
  }[s.level];

  return (
    <div
      className="card overflow-hidden"
      style={{ borderColor: `${levelColor}30`, backgroundColor: levelBg }}
    >
      {/* Header Row */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-white/5 transition-colors"
      >
        {levelIcon}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13px] font-bold" style={{ color: levelColor }}>
              {levelLabel}
            </span>
            {s.riskScore !== null && (
              <span className="text-[11px] font-semibold text-mono px-2 py-0.5 rounded"
                style={{ color: levelColor, backgroundColor: `${levelColor}18` }}>
                Risk {s.riskScore}/100
              </span>
            )}
            {s.tlsVersion && (
              <span className="text-[11px] font-medium text-mono px-2 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-text-secondary)]">
                <Lock size={9} className="inline mr-1" />{s.tlsVersion}
              </span>
            )}
            {!s.tlsVersion && s.level !== 'unknown' && (
              <span className="text-[11px] font-bold text-[var(--color-severity-critical)] px-2 py-0.5 rounded bg-[var(--color-severity-critical-bg)]">
                <LockOpen size={9} className="inline mr-1" />NO ENCRYPTION
              </span>
            )}
            {s.findingsCount > 0 && (
              <span className="text-[11px] font-semibold text-[var(--color-severity-critical)] px-2 py-0.5 rounded bg-[var(--color-severity-critical-bg)]">
                <AlertTriangle size={9} className="inline mr-1" />{s.findingsCount} Finding{s.findingsCount > 1 ? 's' : ''}
              </span>
            )}
          </div>
          <div className="text-[11px] text-[var(--color-text-muted)] mt-0.5">
            {session ? `Session ${session.id} • ${session.sourceIp} → ${session.destHostname || session.destIp}` : 'Transport security analysis'}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          {session && (
            <Link
              href={`/sessions/${session.id}`}
              onClick={e => e.stopPropagation()}
              className="flex items-center gap-1 px-2 py-1 text-[11px] font-medium rounded-md text-[var(--color-accent)] hover:bg-[var(--color-accent-dim)] transition-colors border border-[rgba(56,189,248,0.15)]"
            >
              <Eye size={11} />
              View Session
            </Link>
          )}
          <ChevronRight
            size={14}
            className={clsx('text-[var(--color-text-muted)] transition-transform duration-200', expanded && 'rotate-90')}
          />
        </div>
      </button>

      {/* Expanded Details */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-[rgba(255,255,255,0.06)]">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-4">
            <SecurityField
              label="TLS Version"
              value={s.tlsVersion || 'None'}
              status={!s.tlsVersion ? 'critical' : s.tlsVersion === 'TLS 1.3' ? 'secure' : s.tlsVersion === 'TLS 1.2' ? 'acceptable' : 'critical'}
              mono
            />
            <SecurityField
              label="Forward Secrecy"
              value={s.forwardSecrecy === true ? '✓ Observed' : s.forwardSecrecy === false ? '✕ Not Observed' : 'N/A'}
              status={s.forwardSecrecy === true ? 'secure' : s.forwardSecrecy === false ? 'critical' : 'unknown'}
            />
            <SecurityField
              label="Certificate"
              value={s.certificateStatus ? s.certificateStatus.toUpperCase() : 'N/A'}
              status={s.certificateStatus === 'valid' ? 'secure' : s.certificateStatus === 'expiring' ? 'warning' : s.certificateStatus === 'expired' ? 'critical' : 'unknown'}
            />
            <SecurityField
              label="STARTTLS"
              value={s.starttls === true ? '✓ Negotiated' : s.starttls === false ? '✕ Not Used' : 'N/A'}
              status={s.starttls === true ? 'secure' : s.starttls === false ? 'critical' : 'unknown'}
            />
            {s.cipher && (
              <div className="col-span-2">
                <SecurityField label="Cipher Suite" value={s.cipher} status="acceptable" mono />
              </div>
            )}
            {s.anomalyScore !== null && (
              <SecurityField
                label="AI Anomaly Score"
                value={`${s.anomalyScore}/100`}
                status={s.anomalyScore >= 70 ? 'critical' : s.anomalyScore >= 40 ? 'warning' : 'secure'}
                mono
              />
            )}
            {session && (
              <div className="col-span-2 md:col-span-4 flex items-center gap-3 pt-2">
                <Link
                  href={`/sessions/${session.id}`}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium rounded-md text-[var(--color-accent)] bg-[var(--color-accent-dim)] hover:bg-[rgba(56,189,248,0.15)] transition-colors border border-[rgba(56,189,248,0.15)]"
                >
                  <Network size={12} />
                  Forensic Session {session.id}
                  <ExternalLink size={10} />
                </Link>
                {findings.length > 0 && (
                  <Link
                    href="/findings"
                    className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium rounded-md text-[var(--color-severity-critical)] bg-[var(--color-severity-critical-bg)] hover:bg-[rgba(239,68,68,0.12)] transition-colors border border-[rgba(239,68,68,0.15)]"
                  >
                    <AlertTriangle size={12} />
                    {findings.length} Finding{findings.length > 1 ? 's' : ''}
                    <ExternalLink size={10} />
                  </Link>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function SecurityField({ label, value, status, mono }: {
  label: string; value: string; status: string; mono?: boolean;
}) {
  const color = {
    secure: 'var(--color-severity-healthy)',
    warning: 'var(--color-severity-high)',
    acceptable: 'var(--color-text-secondary)',
    critical: 'var(--color-severity-critical)',
    unknown: 'var(--color-text-dim)',
  }[status] || 'var(--color-text-secondary)';

  return (
    <div className="p-2.5 bg-[var(--color-surface-1)] rounded-md border border-[var(--color-border-subtle)]">
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] mb-1">{label}</div>
      <div className={clsx('text-[12px] font-semibold', mono && 'text-mono')} style={{ color }}>
        {value}
      </div>
    </div>
  );
}

function formatDateTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: 'numeric', minute: '2-digit', hour12: true,
  });
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}
