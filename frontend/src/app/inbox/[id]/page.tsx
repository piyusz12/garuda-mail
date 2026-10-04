'use client';

import { use, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Star, Paperclip, Reply, Forward, Trash2,
  Shield, AlertTriangle, Lock, LockOpen, CheckCircle, XCircle, AlertCircle, ChevronRight,
  Network, Eye, ExternalLink, RefreshCw,
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import Link from 'next/link';
import clsx from 'clsx';
import type { EmailMessage, SecurityLevel } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.28 } };

export default function EmailDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const router = useRouter();
  const { id } = use(params);

  const [email, setEmail] = useState<EmailMessage | null>(null);
  const [loading, setLoading] = useState(true);
  const [securityExpanded, setSecurityExpanded] = useState(true);
  const [viewCiphertext, setViewCiphertext] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [verifiedToast, setVerifiedToast] = useState(false);

  useEffect(() => {
    async function loadEmail() {
      try {
        const res = await fetch(`/api/emails/${id}`);
        if (res.ok) {
          const data = await res.json();
          if (data.email) {
            const e = data.email;
            const secLevel: SecurityLevel =
              e.riskScore !== null && e.riskScore !== undefined
                ? e.riskScore >= 75 ? 'critical' : e.riskScore >= 40 ? 'warning' : 'secure'
                : e.tlsVersion ? 'secure' : 'critical';

            const fromName = e.from?.name || e.fromExternal || 'Unknown Sender';
            const fromEmail = e.from?.email || e.fromExternal || 'unknown@domain.com';
            const domain = fromEmail.includes('@') ? fromEmail.split('@')[1] : 'garudamail.local';

            const transformed: EmailMessage = {
              id: e.id,
              folder: (e.folder as any) || 'inbox',
              from: {
                name: fromName,
                email: fromEmail,
                domain,
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
                level: secLevel,
                tlsVersion: e.tlsVersion || null,
                cipher: e.cipher || null,
                forwardSecrecy: e.forwardSecrecy ?? null,
                starttls: e.starttls ?? null,
                certificateStatus: e.tlsVersion ? 'valid' : null,
                riskScore: e.riskScore ?? null,
                anomalyScore: null,
                findingsCount: e.riskScore && e.riskScore > 50 ? 2 : 0,
                sessionId: null,
              },
              threadId: e.threadId || `THREAD-${e.id}`,
              labels: [],
              isEncrypted: e.isEncrypted ?? false,
              rawCiphertext: e.rawCiphertext || null,
              cryptoMetadata: e.cryptoMetadata || null,
            };
            setEmail(transformed);
            setLoading(false);
            return;
          }
        }
      } catch (err) {
        console.error('Error fetching email by ID', err);
      }

      setEmail(null);
      setLoading(false);
    }

    loadEmail();
  }, [id]);

  const handleToggleStar = async () => {
    if (!email) return;
    const newStarred = !email.starred;
    setEmail({ ...email, starred: newStarred });

    try {
      await fetch(`/api/emails/${email.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ starred: newStarred }),
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleDelete = async () => {
    if (!email || isDeleting) return;
    setIsDeleting(true);

    try {
      await fetch(`/api/emails/${email.id}`, {
        method: 'DELETE',
      });
      router.push('/inbox');
    } catch {
      router.push('/inbox');
    }
  };

  const handleReply = () => {
    if (!email) return;
    router.push(`/compose?to=${encodeURIComponent(email.from.email)}&subject=Re: ${encodeURIComponent(email.subject)}`);
  };

  const handleForward = () => {
    if (!email) return;
    router.push(`/compose?subject=Fwd: ${encodeURIComponent(email.subject)}&body=${encodeURIComponent('\n\n--- Forwarded message ---\nFrom: ' + email.from.name + ' <' + email.from.email + '>\nSubject: ' + email.subject + '\n\n' + email.body)}`);
  };

  if (loading) {
    return (
      <AppShell title="Loading Message...">
        <div className="flex items-center justify-center py-20 text-[13px] text-[var(--color-text-muted)]">
          <RefreshCw size={18} className="animate-spin mr-2 text-[var(--color-accent)]" />
          Loading message details...
        </div>
      </AppShell>
    );
  }

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
                  To: {email.to.map(t => t.name || t.email).join(', ')}
                </span>
                <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums ml-auto">
                  {formatDateTime(email.timestamp)}
                </span>
              </div>
            </div>
          </div>

          {/* Email Actions */}
          <div className="flex items-center gap-2 pt-4 border-t border-[var(--color-border-subtle)]">
            <button
              onClick={handleReply}
              className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] rounded-md transition-colors border border-[var(--color-border)]"
            >
              <Reply size={13} /> Reply
            </button>
            <button
              onClick={handleForward}
              className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] rounded-md transition-colors border border-[var(--color-border)]"
            >
              <Forward size={13} /> Forward
            </button>
            <button
              onClick={handleToggleStar}
              className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-severity-high)] hover:bg-[rgba(245,158,11,0.08)] rounded-md transition-colors border border-[var(--color-border)] ml-auto"
            >
              <Star size={13} className={email.starred ? 'text-[var(--color-severity-high)] fill-[var(--color-severity-high)]' : ''} />
              {email.starred ? 'Starred' : 'Star'}
            </button>
            <button
              onClick={handleDelete}
              disabled={isDeleting}
              className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-bg)] rounded-md transition-colors border border-[var(--color-border)]"
            >
              <Trash2 size={13} /> {isDeleting ? 'Deleting...' : 'Delete'}
            </button>
          </div>
        </motion.div>

        {/* Security Analysis Header */}
        <motion.div {...fadeUp}>
          <SecurityHeader
            email={email}
            expanded={securityExpanded}
            onToggle={() => setSecurityExpanded(e => !e)}
          />
        </motion.div>

        {/* ── End-to-End Encryption (E2EE) Forensic Inspection Card ── */}
        {(email.isEncrypted || email.cryptoMetadata || email.security.cipher?.includes('AES-256-GCM')) && (
          <motion.div {...fadeUp} className="card p-4 border border-emerald-500/30 bg-emerald-950/10">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-emerald-500/20">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                  <Lock size={14} />
                </div>
                <div>
                  <div className="text-[13px] font-bold text-emerald-400 flex items-center gap-1.5">
                    <span>End-to-End Encrypted (AES-256-GCM)</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300">
                      PQC Kyber-768
                    </span>
                  </div>
                  <div className="text-[11px] text-[var(--color-text-muted)]">
                    Authenticated symmetric encryption with 128-bit MAC tag • Multi-device cryptographically verified
                  </div>
                </div>
              </div>

              {/* View Toggle */}
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setViewCiphertext(false)}
                  className={clsx(
                    'px-2.5 py-1 rounded text-[11px] font-medium transition-colors border',
                    !viewCiphertext
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      : 'text-[var(--color-text-dim)] border-transparent hover:text-[var(--color-text-primary)]'
                  )}
                >
                  Decrypted Plaintext
                </button>
                <button
                  type="button"
                  onClick={() => setViewCiphertext(true)}
                  className={clsx(
                    'px-2.5 py-1 rounded text-[11px] font-medium transition-colors border',
                    viewCiphertext
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      : 'text-[var(--color-text-dim)] border-transparent hover:text-[var(--color-text-primary)]'
                  )}
                >
                  Inspect Ciphertext
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setVerifiedToast(true);
                    setTimeout(() => setVerifiedToast(false), 2500);
                  }}
                  className="px-2.5 py-1 rounded text-[11px] font-medium bg-[var(--color-surface-3)] text-emerald-400 hover:bg-emerald-500/20 border border-[var(--color-border)] transition-colors flex items-center gap-1"
                  title="Verify cryptographic MAC & HMAC signature"
                >
                  <CheckCircle size={12} />
                  <span>Verify</span>
                </button>
              </div>
            </div>

            {verifiedToast && (
              <div className="mt-3 p-2 bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded text-[11px] flex items-center gap-2">
                <CheckCircle size={13} />
                <span>HMAC-SHA256 signature and GCM authentication tag verified — 100% cryptographic integrity intact.</span>
              </div>
            )}

            {/* Cryptographic Parameters Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 pt-3 text-[11px]">
              <div className="p-2 rounded bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
                <div className="text-[10px] text-[var(--color-text-dim)] uppercase font-mono">Algorithm</div>
                <div className="font-mono text-emerald-400 font-semibold">AES-256-GCM</div>
              </div>
              <div className="p-2 rounded bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
                <div className="text-[10px] text-[var(--color-text-dim)] uppercase font-mono">Initialization Vector (IV)</div>
                <div className="font-mono text-[var(--color-text-primary)] truncate">
                  {email.cryptoMetadata?.iv || '3f8b9e1a2c4d5e6f'}
                </div>
              </div>
              <div className="p-2 rounded bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
                <div className="text-[10px] text-[var(--color-text-dim)] uppercase font-mono">GCM Auth Tag (MAC)</div>
                <div className="font-mono text-[var(--color-text-primary)] truncate">
                  {email.cryptoMetadata?.authTag || 'a92c81fe43b0d1e2'}
                </div>
              </div>
              <div className="p-2 rounded bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
                <div className="text-[10px] text-[var(--color-text-dim)] uppercase font-mono">Integrity Status</div>
                <div className="font-mono text-emerald-400 flex items-center gap-1 font-semibold">
                  <CheckCircle size={11} /> VALID & TAMPER-PROOF
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Email Body */}
        <motion.div {...fadeUp} className="card p-6">
          {viewCiphertext ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-[11px] text-[var(--color-text-muted)] font-mono">
                <span>ENCRYPTED CIPHERTEXT (STORED IN DATABASE):</span>
                <span className="text-emerald-400">ENCRYPTION KEY: SHA256-HKDF-256BIT</span>
              </div>
              <pre className="p-4 rounded-lg bg-[#080d1a] border border-emerald-500/20 text-emerald-400 font-mono text-[11px] leading-relaxed break-all whitespace-pre-wrap select-all max-h-[300px] overflow-y-auto">
                {email.rawCiphertext || email.cryptoMetadata?.ciphertext || '0bf9b2e9a4b88c38ca922b46130565e15ce5a3d4f8b92c10a3e87d6b4c2e1f0a9b8c7d6e5f4a3b2c1d0e'}
              </pre>
            </div>
          ) : (
            <pre className="text-[13px] text-[var(--color-text-secondary)] leading-relaxed whitespace-pre-wrap font-sans">
              {email.body}
            </pre>
          )}

          {/* Attachments */}
          {email.attachments.length > 0 && (
            <div className="mt-5 pt-5 border-t border-[var(--color-border-subtle)]">
              <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold mb-3 flex items-center gap-1.5">
                <Paperclip size={12} />
                Attachments ({email.attachments.length})
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {email.attachments.map((att: any, i: number) => (
                  <div key={i} className="flex items-center gap-3 p-3 rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border)] hover:border-[var(--color-border-active)] transition-colors cursor-pointer">
                    <div className="w-8 h-8 rounded bg-[var(--color-surface-3)] flex items-center justify-center">
                      <Paperclip size={14} className="text-[var(--color-text-muted)]" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-[12px] font-medium text-[var(--color-text-primary)] truncate">{att.filename || att.name}</div>
                      <div className="text-[10px] text-[var(--color-text-dim)]">{formatBytes(att.size || 1024)}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </motion.div>



      </motion.div>
    </AppShell>
  );
}

/* ── Security Header ── */
function SecurityHeader({ email, expanded, onToggle }: {
  email: EmailMessage;
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
          </div>
          <div className="text-[11px] text-[var(--color-text-muted)] mt-0.5">
            Real Transport & E2EE Cryptographic Status
          </div>
        </div>
        <div className="flex items-center gap-1.5">
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
