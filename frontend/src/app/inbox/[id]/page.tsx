'use client';

import { use, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Star, Paperclip, Reply, Forward, Trash2,
  Shield, AlertTriangle, Lock, LockOpen, CheckCircle, XCircle, AlertCircle, ChevronRight,
  Network, Eye, ExternalLink, RefreshCw, ShieldCheck, ShieldAlert
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { getEmailById } from '@/lib/mock/emails';
import { mockFindings, mockSessions } from '@/lib/mock/data';
import Link from 'next/link';
import clsx from 'clsx';
import type { EmailMessage, SecurityLevel } from '@/types/email';

const fadeUp = { initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function EmailDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const router = useRouter();
  const { id } = use(params);

  const [email, setEmail] = useState<EmailMessage | null>(null);
  const [loading, setLoading] = useState(true);
  const [isDeleting, setIsDeleting] = useState(false);

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
            const domain = fromEmail.includes('@') ? fromEmail.split('@')[1] : 'enterprise.local';

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
            };
            setEmail(transformed);
            setLoading(false);
            return;
          }
        }
      } catch (err) {
        console.error('Error fetching email by ID', err);
      }

      // Fallback to mock data if ID matches mock or DB request failed
      const mock = getEmailById(id);
      setEmail(mock || null);
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
      <AppShell title="Message Investigation">
        <div className="flex flex-col items-center justify-center py-32 text-[13px] text-[var(--color-text-muted)]">
          <RefreshCw size={24} className="animate-spin mb-4 text-[var(--color-accent)]" />
          <div className="font-medium tracking-wide uppercase">Decrypting payload...</div>
        </div>
      </AppShell>
    );
  }

  if (!email) {
    return (
      <AppShell title="Record Not Found">
        <div className="flex flex-col items-center justify-center py-32">
          <Shield size={48} className="text-[var(--color-text-dim)] mb-6" />
          <h2 className="text-xl font-semibold mb-2 text-[var(--color-text-primary)] tracking-tight">Record Not Found</h2>
          <p className="text-[14px] text-[var(--color-text-muted)] mb-6">The requested message does not exist or has been purged.</p>
          <Link href="/inbox" className="text-[13px] font-medium text-[var(--color-text-primary)] bg-[var(--color-surface-2)] border border-[var(--color-border)] hover:bg-[var(--color-surface-3)] transition-colors px-4 py-2 rounded-lg">
            Return to Inbox
          </Link>
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

  const btnBase = "flex items-center justify-center gap-2 px-3 py-1.5 text-[12px] font-medium rounded-lg transition-all duration-200 border shadow-sm whitespace-nowrap";
  const btnDefault = `${btnBase} border-[var(--color-border-subtle)] bg-[var(--color-surface-2)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] hover:border-[var(--color-border)]`;
  const btnDanger = `${btnBase} border-[var(--color-severity-critical)]/30 bg-[var(--color-severity-critical-bg)] text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical)]/20`;
  const btnStarred = `${btnBase} border-[var(--color-severity-high)]/30 bg-[rgba(245,158,11,0.08)] text-[var(--color-severity-high)] hover:bg-[rgba(245,158,11,0.15)]`;

  return (
    <AppShell
      title="Message Investigation"
      description={`ID: ${email.id} • ${formatDateTime(email.timestamp)}`}
    >
      <motion.div initial="initial" animate="animate" className="flex flex-col lg:flex-row gap-6 max-w-[1400px] mx-auto pb-12">

        {/* Left Column - Main Content (Approx 65%) */}
        <div className="flex-1 flex flex-col min-w-0 space-y-4">

          {/* Top Nav & Context */}
          <motion.div {...fadeUp} className="flex items-center justify-between mb-1 px-1">
            <Link href="/inbox" className="inline-flex items-center gap-1.5 text-[13px] font-medium text-[var(--color-text-muted)] hover:text-[var(--color-accent)] transition-colors group">
              <ArrowLeft size={16} className="transition-transform group-hover:-translate-x-1" /> Back to Inbox
            </Link>
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--color-severity-healthy)] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--color-severity-healthy)]"></span>
              </span>
              <span className="text-[11px] font-bold text-[var(--color-severity-healthy)] uppercase tracking-wider">Live</span>
            </div>
          </motion.div>

          {/* Email Header */}
          <motion.div {...fadeUp} className="card p-5 sm:p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
            <h1 className="text-[20px] sm:text-[22px] font-bold text-[var(--color-text-primary)] leading-snug mb-5 tracking-tight break-words">
              {email.subject}
            </h1>

            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 border-b border-[var(--color-border-subtle)] pb-5 mb-5">
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-10 h-10 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] flex items-center justify-center text-[14px] font-bold text-[var(--color-text-secondary)] shadow-inner flex-shrink-0">
                  {email.from.name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[14px] font-semibold text-[var(--color-text-primary)] truncate">{email.from.name}</span>
                    <span className="text-[10px] text-[var(--color-text-dim)] font-mono bg-[var(--color-surface-2)] px-1.5 py-0.5 rounded border border-[var(--color-border-subtle)] hidden sm:inline-block">
                      {email.from.domain}
                    </span>
                  </div>
                  <div className="text-[12px] text-[var(--color-text-muted)] truncate mt-0.5">
                    <span className="opacity-70">From:</span> <span className="text-[var(--color-text-secondary)]">{email.from.email}</span>
                  </div>
                  <div className="text-[12px] text-[var(--color-text-muted)] truncate mt-0.5">
                    <span className="opacity-70">To:</span> <span className="text-[var(--color-text-secondary)]">{email.to.map(t => t.name || t.email).join(', ')}</span>
                  </div>
                </div>
              </div>
              <div className="text-[12px] text-[var(--color-text-dim)] tabular-nums font-medium sm:text-right mt-1 flex-shrink-0">
                {formatDateTime(email.timestamp)}
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 overflow-x-auto hide-scrollbar pb-1">
              <button onClick={handleReply} className={btnDefault}><Reply size={14} /> Reply</button>
              <button onClick={handleForward} className={btnDefault}><Forward size={14} /> Forward</button>
              <button onClick={handleToggleStar} className={email.starred ? btnStarred : btnDefault}>
                <Star size={14} className={email.starred ? 'fill-current' : ''} /> {email.starred ? 'Starred' : 'Star'}
              </button>
              <div className="w-px h-4 bg-[var(--color-border)] mx-1 sm:mx-2 hidden sm:block" />
              <button onClick={handleDelete} disabled={isDeleting} className={`${btnDanger} sm:ml-auto`}>
                <Trash2 size={14} /> {isDeleting ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </motion.div>

          {/* Message Body */}
          <motion.div {...fadeUp} className="card flex-1 flex flex-col p-5 sm:p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl min-h-[400px]">
            <div className="text-[11px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-4 flex items-center gap-2 border-b border-[var(--color-border-subtle)] pb-3">
              <div className="w-1.5 h-1.5 rounded-full bg-[var(--color-text-dim)]" />
              Message Payload
            </div>
            <div className="flex-1 overflow-x-auto">
              <pre className="text-[14px] text-[var(--color-text-primary)] leading-relaxed whitespace-pre-wrap font-sans">
                {email.body}
              </pre>
            </div>

            {/* Attachments */}
            {email.attachments.length > 0 && (
              <div className="mt-6 pt-5 border-t border-[var(--color-border-subtle)]">
                <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold mb-3 flex items-center gap-1.5">
                  <Paperclip size={12} />
                  Attachments ({email.attachments.length})
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {email.attachments.map((att: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] transition-colors cursor-pointer group">
                      <div className="w-8 h-8 rounded-md bg-[var(--color-surface-3)] flex items-center justify-center group-hover:bg-[var(--color-surface-1)] transition-colors border border-transparent group-hover:border-[var(--color-border)]">
                        <Paperclip size={14} className="text-[var(--color-text-muted)] group-hover:text-[var(--color-text-primary)] transition-colors" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-[12px] font-medium text-[var(--color-text-primary)] truncate">{att.filename || att.name}</div>
                        <div className="text-[10px] text-[var(--color-text-dim)] font-mono mt-0.5">{formatBytes(att.size || 1024)}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </motion.div>

        </div>

        {/* Right Column - Security Intelligence (Approx 35%) */}
        <div className="lg:w-[380px] xl:w-[420px] flex-shrink-0 space-y-4">
          <motion.div {...fadeUp}>
            <SecurityIntelligencePanel email={email} session={session} findings={findings} />
          </motion.div>

          {/* Findings Block */}
          {findings.length > 0 && (
            <motion.div {...fadeUp} className="card p-5 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
              <div className="flex items-center gap-2 mb-4 border-b border-[var(--color-border-subtle)] pb-3">
                <AlertTriangle size={14} className="text-[var(--color-severity-critical)]" />
                <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-primary)] font-bold">
                  Security Findings
                </span>
                <span className="text-[10px] tabular-nums bg-[var(--color-severity-critical-bg)] text-[var(--color-severity-critical)] px-1.5 py-0.5 rounded font-semibold ml-auto border border-[var(--color-severity-critical)]/20">
                  {findings.length}
                </span>
              </div>
              <div className="space-y-2">
                {findings.map(f => (
                  <Link
                    key={f.id}
                    href={`/findings/${f.id}`}
                    className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] transition-colors group border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] shadow-sm"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <SeverityBadge severity={f.severity} size="xs" />
                      <div className="min-w-0">
                        <div className="text-[13px] font-medium text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] transition-colors truncate">
                          {f.title}
                        </div>
                        <div className="text-[10px] text-[var(--color-text-dim)] font-mono mt-0.5 truncate">
                          {f.id} • {f.category}
                        </div>
                      </div>
                    </div>
                    <ChevronRight size={14} className="flex-shrink-0 text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors" />
                  </Link>
                ))}
              </div>
            </motion.div>
          )}
        </div>

      </motion.div>
    </AppShell>
  );
}

function SecurityIntelligencePanel({ email, session, findings }: { email: EmailMessage, session: any, findings: any[] }) {
  const s = email.security;
  const isCritical = s.level === 'critical';
  const isWarning = s.level === 'warning';
  const isSecure = s.level === 'secure';

  const levelColor = isCritical ? 'var(--color-severity-critical)' :
                     isWarning ? 'var(--color-severity-high)' :
                     isSecure ? 'var(--color-severity-healthy)' : 'var(--color-text-dim)';

  const levelBg = isCritical ? 'var(--color-severity-critical-bg)' :
                  isWarning ? 'rgba(245, 158, 11, 0.05)' :
                  isSecure ? 'rgba(16, 185, 129, 0.05)' : 'var(--color-surface-2)';

  const levelBorder = isCritical ? 'rgba(239, 68, 68, 0.3)' :
                      isWarning ? 'rgba(245, 158, 11, 0.3)' :
                      isSecure ? 'rgba(16, 185, 129, 0.3)' : 'var(--color-border-subtle)';

  const SecIcon = isCritical ? ShieldAlert :
                  isWarning ? AlertTriangle :
                  isSecure ? ShieldCheck : Shield;

  const levelLabel = isCritical ? 'CRITICAL RISK' :
                     isWarning ? 'SECURITY WARNING' :
                     isSecure ? 'SECURE' : 'UNKNOWN';

  return (
    <div className="card overflow-hidden border bg-[var(--color-surface-1)] shadow-md rounded-xl relative" style={{ borderColor: levelBorder }}>
      {/* Background ambient glow */}
      {s.level !== 'unknown' && (
        <div className="absolute -top-24 -right-24 w-48 h-48 rounded-full blur-3xl opacity-20 pointer-events-none transition-colors duration-500" style={{ backgroundColor: levelColor }} />
      )}

      {/* Main Status Header */}
      <div className="p-6 border-b border-[var(--color-border-subtle)]" style={{ backgroundColor: levelBg }}>
        <div className="flex items-center gap-2 mb-5">
          <SecIcon size={16} style={{ color: levelColor }} />
          <h2 className="text-[11px] font-bold tracking-widest uppercase" style={{ color: levelColor }}>Intelligence Report</h2>
        </div>

        <div className="flex flex-col gap-4">
          <div className="flex items-end justify-between">
            <div>
              <div className="text-[40px] font-bold tracking-tighter leading-none mb-1 drop-shadow-sm" style={{ color: levelColor }}>
                {s.riskScore !== null ? s.riskScore : '--'}
                <span className="text-[16px] text-[var(--color-text-dim)] font-medium ml-1">/ 100</span>
              </div>
              <div className="text-[12px] font-bold text-[var(--color-text-primary)] tracking-wider mt-1 uppercase">
                {levelLabel}
              </div>
            </div>

            <div className="flex flex-col items-end gap-2 z-10">
              {s.tlsVersion ? (
                <div className="flex items-center gap-1.5 px-2.5 py-1 bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded shadow-sm">
                  <Lock size={12} className={s.tlsVersion === 'TLS 1.3' ? "text-[var(--color-severity-healthy)]" : "text-[var(--color-text-secondary)]"} />
                  <span className="text-[11px] font-mono font-bold text-[var(--color-text-primary)]">{s.tlsVersion}</span>
                </div>
              ) : s.level !== 'unknown' ? (
                <div className="flex items-center gap-1.5 px-2.5 py-1 bg-[var(--color-severity-critical-bg)] border border-[var(--color-severity-critical)]/30 rounded shadow-sm">
                  <LockOpen size={12} className="text-[var(--color-severity-critical)]" />
                  <span className="text-[11px] font-mono font-bold text-[var(--color-severity-critical)]">NO TLS</span>
                </div>
              ) : null}

              {s.findingsCount > 0 && (
                <div className="flex items-center gap-1.5 px-2.5 py-1 bg-[var(--color-surface-1)] border border-[var(--color-severity-critical)]/30 rounded shadow-sm">
                  <AlertTriangle size={12} className="text-[var(--color-severity-critical)]" />
                  <span className="text-[11px] font-bold text-[var(--color-severity-critical)]">{s.findingsCount} Findings</span>
                </div>
              )}
            </div>
          </div>

          {/* Risk Progress Bar */}
          {s.riskScore !== null && (
            <div className="w-full h-1.5 bg-[var(--color-surface-3)] rounded-full mt-2 overflow-hidden shadow-inner relative z-10">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${s.riskScore}%` }}
                transition={{ duration: 1, ease: "easeOut" }}
                className="h-full rounded-full relative"
                style={{ backgroundColor: levelColor }}
              >
                 <div className="absolute inset-0 bg-gradient-to-r from-transparent to-white/20" />
              </motion.div>
            </div>
          )}
        </div>
      </div>

      {/* Technical Metadata Grid */}
      <div className="p-6 space-y-4 relative z-10">
        <div className="text-[11px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-1">Technical Metadata</div>
        <div className="grid grid-cols-2 gap-3">
          <SecurityField
            label="TLS Version"
            value={s.tlsVersion || 'None'}
            status={!s.tlsVersion ? 'critical' : s.tlsVersion === 'TLS 1.3' ? 'secure' : s.tlsVersion === 'TLS 1.2' ? 'warning' : 'critical'}
            mono
          />
          <SecurityField
            label="Forward Secrecy"
            value={s.forwardSecrecy === true ? 'Observed' : s.forwardSecrecy === false ? 'Not Observed' : 'N/A'}
            status={s.forwardSecrecy === true ? 'secure' : s.forwardSecrecy === false ? 'critical' : 'unknown'}
          />
          <SecurityField
            label="Certificate"
            value={s.certificateStatus ? s.certificateStatus.toUpperCase() : 'N/A'}
            status={s.certificateStatus === 'valid' ? 'secure' : s.certificateStatus === 'expiring' ? 'warning' : s.certificateStatus === 'expired' ? 'critical' : 'unknown'}
          />
          <SecurityField
            label="STARTTLS"
            value={s.starttls === true ? 'Negotiated' : s.starttls === false ? 'Not Used' : 'N/A'}
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

        {/* Investigation Actions */}
        {(session || (findings.length > 0 && !session)) && (
          <div className="mt-4 pt-5 border-t border-[var(--color-border-subtle)] space-y-2">
            {session && (
              <Link
                href={`/sessions/${session.id}`}
                className="flex items-center justify-between px-4 py-2.5 text-[12px] font-medium rounded-lg text-[var(--color-accent)] bg-[var(--color-accent-dim)] hover:bg-[rgba(56,189,248,0.15)] transition-colors border border-[rgba(56,189,248,0.2)] group shadow-sm"
              >
                <div className="flex items-center gap-2.5">
                  <Network size={14} />
                  <span>View Forensic Session</span>
                </div>
                <ExternalLink size={14} className="opacity-50 group-hover:opacity-100 transition-opacity" />
              </Link>
            )}
            {findings.length > 0 && !session && (
              <Link
                href="/findings"
                className="flex items-center justify-between px-4 py-2.5 text-[12px] font-medium rounded-lg text-[var(--color-severity-critical)] bg-[var(--color-severity-critical-bg)] hover:bg-[rgba(239,68,68,0.12)] transition-colors border border-[rgba(239,68,68,0.2)] group shadow-sm"
              >
                <div className="flex items-center gap-2.5">
                  <AlertTriangle size={14} />
                  <span>Review {findings.length} Finding{findings.length > 1 ? 's' : ''}</span>
                </div>
                <ExternalLink size={14} className="opacity-50 group-hover:opacity-100 transition-opacity" />
              </Link>
            )}
          </div>
        )}
      </div>
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
    <div className="flex flex-col gap-1 p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] shadow-sm">
      <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-semibold">{label}</div>
      <div className={clsx('text-[12px] font-bold truncate', mono && 'text-mono')} style={{ color }} title={value}>
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
