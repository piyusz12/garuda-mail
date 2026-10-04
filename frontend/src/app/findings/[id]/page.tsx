'use client';

import { use, useState } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Shield, Brain, AlertTriangle, ExternalLink,
  Copy, Check, CheckCircle, FileText, Bookmark, ChevronRight,
  Info, Target, Layers, ClipboardCheck, ShieldAlert, ShieldCheck,
  Activity, Server, Network
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, StatusBadge } from '@/components/ui/shared';
import { mockFindings, mockSessions } from '@/lib/mock/data';
import { formatDateTime } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';
import type { Finding, Evidence } from '@/types';

const fadeUp = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.3 },
};

export default function FindingDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const finding = mockFindings.find(f => f.id === id);
  const [copied, setCopied] = useState(false);
  const [isReviewed, setIsReviewed] = useState(finding?.status === 'reviewed');

  const handleCopyRecommendation = () => {
    if (finding?.remediation) {
      navigator.clipboard.writeText(finding.remediation);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  const handleToggleReviewed = () => {
    setIsReviewed(prev => !prev);
  };

  if (!finding) {
    return (
      <AppShell title="Finding Not Found" description="The requested finding does not exist">
        <div className="flex flex-col items-center justify-center py-32">
          <AlertTriangle size={48} className="text-[var(--color-text-dim)] mb-6" />
          <h2 className="text-xl font-bold text-[var(--color-text-primary)] mb-2 tracking-tight">Record Not Found</h2>
          <p className="text-[14px] text-[var(--color-text-muted)] mb-6">No finding with ID <span className="font-mono text-[var(--color-text-secondary)]">{id}</span> exists in the current telemetry.</p>
          <Link href="/findings" className="text-[13px] font-medium text-[var(--color-text-primary)] bg-[var(--color-surface-2)] border border-[var(--color-border)] hover:bg-[var(--color-surface-3)] transition-colors px-4 py-2 rounded-lg shadow-sm">
            Return to Findings
          </Link>
        </div>
      </AppShell>
    );
  }

  // Derived styling based on severity
  const isCritical = finding.severity === 'critical';
  const isHigh = finding.severity === 'high';
  const isMedium = finding.severity === 'medium';

  const levelColor = isCritical ? 'var(--color-severity-critical)' :
                     isHigh ? 'var(--color-severity-high)' :
                     isMedium ? 'var(--color-severity-medium)' :
                     finding.severity === 'low' ? 'var(--color-severity-low)' : 'var(--color-text-dim)';

  const levelBg = isCritical ? 'var(--color-severity-critical-bg)' :
                  isHigh ? 'rgba(245, 158, 11, 0.05)' :
                  isMedium ? 'rgba(234, 179, 8, 0.05)' :
                  finding.severity === 'low' ? 'rgba(56, 189, 248, 0.05)' : 'var(--color-surface-2)';

  const levelBorder = isCritical ? 'rgba(239, 68, 68, 0.3)' :
                      isHigh ? 'rgba(245, 158, 11, 0.3)' :
                      isMedium ? 'rgba(234, 179, 8, 0.3)' :
                      finding.severity === 'low' ? 'rgba(56, 189, 248, 0.3)' : 'var(--color-border-subtle)';

  const SecIcon = isCritical ? ShieldAlert :
                  isHigh ? AlertTriangle :
                  isMedium ? AlertTriangle :
                  finding.severity === 'low' ? Info : ShieldCheck;

  return (
    <AppShell title={`Incident ${finding.id}`} description={finding.title}>
      <motion.div initial="initial" animate="animate" className="flex flex-col lg:flex-row gap-6 max-w-[1400px] mx-auto pb-12">

        {/* ── Left Column - Main Content (~65%) ── */}
        <div className="flex-1 flex flex-col min-w-0 space-y-4">

          {/* Back nav & Context */}
          <motion.div {...fadeUp} className="flex items-center justify-between mb-1 px-1">
            <Link href="/findings" className="inline-flex items-center gap-1.5 text-[13px] font-medium text-[var(--color-text-muted)] hover:text-[var(--color-accent)] transition-colors group">
              <ArrowLeft size={16} className="transition-transform group-hover:-translate-x-1" /> Back to Findings
            </Link>
          </motion.div>

          {/* Finding Header */}
          <motion.div {...fadeUp} className="card p-6 sm:p-7 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-5 border-b border-[var(--color-border-subtle)] pb-6 mb-6">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-3 flex-wrap">
                  <span className="text-[12px] text-mono font-bold text-[var(--color-text-primary)] bg-[var(--color-surface-3)] px-2.5 py-1 rounded border border-[var(--color-border-subtle)]">{finding.id}</span>
                  {finding.ruleId && (
                    <span className="text-[11px] text-mono font-bold text-[var(--color-text-dim)] bg-[var(--color-surface-2)] px-2.5 py-1 rounded border border-[var(--color-border-subtle)]">Rule: {finding.ruleId}</span>
                  )}
                  <StatusBadge status={isReviewed ? 'reviewed' : finding.status} />
                </div>
                <h1 className="text-[22px] sm:text-[26px] font-bold text-[var(--color-text-primary)] leading-snug tracking-tight">
                  {finding.title}
                </h1>
              </div>
              <div className="shrink-0 flex sm:flex-col items-center sm:items-end gap-3 sm:gap-2">
                <SeverityBadge severity={finding.severity} size="md" />
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] shadow-sm text-[11px] font-bold text-[var(--color-text-secondary)] tracking-widest uppercase">
                  {finding.detectionSource === 'ai_anomaly' ? (
                    <><Brain size={12} className="text-[var(--color-accent)]" /> AI Detected</>
                  ) : (
                    <><Shield size={12} className="text-[var(--color-text-muted)]" /> Rule Engine</>
                  )}
                </div>
              </div>
            </div>

            <div className="text-[14px] text-[var(--color-text-secondary)] leading-relaxed bg-[var(--color-surface-2)] p-4 rounded-lg border border-[var(--color-border-subtle)] mb-6 shadow-inner">
              {finding.description}
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center gap-x-6 gap-y-3 text-[12px] font-medium text-[var(--color-text-muted)]">
               <div className="flex items-center gap-1.5">
                  <span className="text-[10px] uppercase tracking-widest font-bold">Category:</span>
                  <span className="text-[var(--color-text-primary)] font-bold">{finding.category}</span>
               </div>
               <div className="hidden sm:block w-px h-4 bg-[var(--color-border-subtle)]" />
               <div className="flex items-center gap-1.5">
                  <span className="text-[10px] uppercase tracking-widest font-bold">Confidence:</span>
                  <span className="text-[var(--color-text-primary)] font-bold tabular-nums">{finding.confidence}%</span>
               </div>
            </div>
          </motion.div>

          {/* Why It Matters */}
          <motion.div {...fadeUp} className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
            <SectionHeader icon={Info} title="Impact Analysis & Context" />
            <p className="text-[14px] text-[var(--color-text-secondary)] leading-relaxed mt-4">{finding.whyItMatters}</p>
          </motion.div>

          {/* Technical Details */}
          <motion.div {...fadeUp} className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
            <SectionHeader icon={Layers} title="Technical Details" />
            <div className="mt-4 p-4 bg-[#0a0a0c] rounded-lg border border-[var(--color-border-subtle)] shadow-inner overflow-x-auto hide-scrollbar">
              <pre className="text-[13px] font-mono text-[var(--color-text-secondary)] leading-relaxed whitespace-pre-wrap">
                {finding.technicalDetails}
              </pre>
            </div>
          </motion.div>

          {/* Remediation */}
          <motion.div {...fadeUp} className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
            <div className="flex items-center justify-between mb-4">
              <SectionHeader icon={CheckCircle} title="Remediation Protocol" />
              <div className="flex items-center gap-2">
                <span className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold">Priority:</span>
                <SeverityBadge severity={finding.remediationPriority} size="xs" />
              </div>
            </div>
            <div className="p-4 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] mb-5">
              <p className="text-[14px] text-[var(--color-text-secondary)] leading-relaxed">{finding.remediation}</p>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center gap-3 pt-5 border-t border-[var(--color-border-subtle)]">
              <button
                type="button"
                onClick={handleCopyRecommendation}
                className="flex items-center justify-center gap-2 px-4 py-2 text-[12px] font-bold text-[var(--color-text-primary)] bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded-lg hover:bg-[var(--color-surface-3)] transition-colors shadow-sm w-full sm:w-auto active:scale-95"
              >
                {copied ? <Check size={14} className="text-[var(--color-severity-healthy)]" /> : <Copy size={14} />}
                {copied ? 'Copied to Clipboard' : 'Copy Recommendation'}
              </button>

              <button
                type="button"
                onClick={handleToggleReviewed}
                className={clsx(
                  "flex items-center justify-center gap-2 px-4 py-2 text-[12px] font-bold rounded-lg border transition-colors shadow-sm w-full sm:w-auto active:scale-95 sm:ml-auto",
                  isReviewed
                    ? "bg-[rgba(52,211,153,0.1)] text-[var(--color-severity-healthy)] border-[rgba(52,211,153,0.3)] hover:bg-[rgba(52,211,153,0.15)]"
                    : "bg-[var(--color-surface-2)] text-[var(--color-text-primary)] border-[var(--color-border)] hover:bg-[var(--color-surface-3)]"
                )}
              >
                {isReviewed ? <CheckCircle size={14} /> : <Bookmark size={14} />}
                {isReviewed ? 'Incident Reviewed' : 'Mark as Reviewed'}
              </button>
            </div>
          </motion.div>

          {/* Evidence Grid */}
          <motion.div {...fadeUp} className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
            <SectionHeader icon={FileText} title="Cryptographic Evidence" count={finding.evidence.length} />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
              {finding.evidence.map((ev, i) => (
                <EvidenceCard key={i} evidence={ev} />
              ))}
            </div>
          </motion.div>

          {/* Standards Mapping */}
          {finding.standardsMapping.length > 0 && (
            <motion.div {...fadeUp} className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
              <SectionHeader icon={ClipboardCheck} title="Compliance & Standards Mapping" count={finding.standardsMapping.length} />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
                {finding.standardsMapping.map((mapping, i) => (
                  <div key={i} className="p-4 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] shadow-sm">
                    <div className="flex items-center justify-between mb-2 pb-2 border-b border-[var(--color-border-subtle)]">
                      <span className="text-[13px] font-bold text-[var(--color-text-primary)]">{mapping.standard}</span>
                      <span className="text-[10px] font-mono font-bold text-[var(--color-text-dim)] bg-[var(--color-surface-3)] px-2 py-0.5 rounded">{mapping.severity}</span>
                    </div>
                    <div className="text-[11px] text-[var(--color-text-muted)] font-mono mb-2 bg-[#0a0a0c] px-2 py-1 rounded inline-block border border-[var(--color-border-subtle)]">{mapping.reference}</div>
                    <div className="text-[12px] font-medium text-[var(--color-text-secondary)] leading-relaxed">{mapping.recommendation}</div>
                  </div>
                ))}
              </div>
            </motion.div>
          )}

        </div>

        {/* ── Right Column - Intelligence Panel (~35%) ── */}
        <div className="lg:w-[380px] xl:w-[420px] flex-shrink-0 space-y-4">

          <motion.div {...fadeUp}>
            <div className="card overflow-hidden border bg-[var(--color-surface-1)] shadow-md rounded-xl relative" style={{ borderColor: levelBorder }}>
              {/* Background ambient glow */}
              <div className="absolute -top-24 -right-24 w-48 h-48 rounded-full blur-3xl opacity-20 pointer-events-none transition-colors duration-500" style={{ backgroundColor: levelColor }} />

              {/* Main Status Header */}
              <div className="p-6 border-b border-[var(--color-border-subtle)]" style={{ backgroundColor: levelBg }}>
                <div className="flex items-center gap-2 mb-5">
                  <SecIcon size={16} style={{ color: levelColor }} />
                  <h2 className="text-[11px] font-bold tracking-widest uppercase" style={{ color: levelColor }}>Finding Assessment</h2>
                </div>

                <div className="flex flex-col gap-5 relative z-10">
                  <div className="flex items-end justify-between">
                    <div>
                      <div className="text-[40px] font-bold tracking-tighter leading-none mb-1 drop-shadow-sm" style={{ color: levelColor }}>
                        {finding.confidence}
                        <span className="text-[16px] text-[var(--color-text-dim)] font-medium ml-1">%</span>
                      </div>
                      <div className="text-[12px] font-bold text-[var(--color-text-primary)] tracking-wider mt-1 uppercase">
                        AI Confidence
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      <div className={clsx(
                        "flex items-center gap-1.5 px-3 py-1.5 border rounded-lg shadow-sm text-[11px] font-bold uppercase tracking-widest",
                        finding.severity === 'critical' ? 'bg-[var(--color-severity-critical-bg)] border-[var(--color-severity-critical)]/30 text-[var(--color-severity-critical)]' :
                        finding.severity === 'high' ? 'bg-[rgba(245,158,11,0.1)] border-[var(--color-severity-high)]/30 text-[var(--color-severity-high)]' :
                        finding.severity === 'medium' ? 'bg-[rgba(234,179,8,0.1)] border-[var(--color-severity-medium)]/30 text-[var(--color-severity-medium)]' :
                        'bg-[var(--color-surface-1)] border-[var(--color-border)] text-[var(--color-text-secondary)]'
                      )}>
                        {finding.severity}
                      </div>
                    </div>
                  </div>

                  {/* Progress Bar */}
                  <div className="w-full h-1.5 bg-[var(--color-surface-3)] rounded-full overflow-hidden shadow-inner">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${finding.confidence}%` }}
                      transition={{ duration: 1, ease: "easeOut" }}
                      className="h-full rounded-full relative"
                      style={{ backgroundColor: levelColor }}
                    >
                       <div className="absolute inset-0 bg-gradient-to-r from-transparent to-white/20" />
                    </motion.div>
                  </div>
                </div>
              </div>

              {/* Finding Metadata Grid */}
              <div className="p-6 space-y-4 relative z-10">
                <div className="text-[11px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-2">Investigation Details</div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="flex flex-col gap-1 p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] shadow-sm">
                    <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold flex items-center gap-1"><Server size={10}/> Affected Assets</div>
                    <div className="text-[18px] font-bold text-[var(--color-text-primary)] tabular-nums leading-none mt-1">{finding.affectedAssets.length}</div>
                    <div className="text-[10px] text-[var(--color-text-muted)] font-mono truncate mt-1">{finding.affectedAssets[0]} {finding.affectedAssets.length > 1 ? ', ...' : ''}</div>
                  </div>

                  <div className="flex flex-col gap-1 p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] shadow-sm">
                    <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold flex items-center gap-1"><Network size={10}/> Related Sessions</div>
                    <div className="text-[18px] font-bold text-[var(--color-text-primary)] tabular-nums leading-none mt-1">{finding.relatedSessionIds.length}</div>
                    <div className="text-[10px] text-[var(--color-text-muted)] mt-1">Network traces</div>
                  </div>

                  <div className="col-span-2 flex flex-col gap-1 p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] shadow-sm">
                    <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold">Category Vector</div>
                    <div className="text-[13px] font-bold text-[var(--color-text-primary)]">{finding.category}</div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Related Sessions Block */}
          {finding.relatedSessionIds.length > 0 && (
            <motion.div {...fadeUp} className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
              <SectionHeader icon={ExternalLink} title="Forensic Sessions" count={finding.relatedSessionIds.length} />
              <div className="space-y-3 mt-4">
                {finding.relatedSessionIds.map(sessionId => {
                  const session = mockSessions.find(s => s.id === sessionId);
                  return (
                    <Link
                      key={sessionId}
                      href={`/sessions/${sessionId}`}
                      className="flex flex-col p-4 rounded-lg bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] transition-all group shadow-sm"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-[13px] font-mono font-bold text-[var(--color-accent)] group-hover:underline">{sessionId}</span>
                        {session && <SeverityBadge severity={session.risk} size="xs" />}
                      </div>
                      {session && (
                        <div className="grid grid-cols-2 gap-2 text-[11px] font-medium text-[var(--color-text-muted)] bg-[var(--color-surface-1)] border border-[var(--color-border-subtle)] p-2.5 rounded">
                          <div>
                            <span className="block text-[9px] font-bold uppercase tracking-widest mb-0.5 opacity-60">Protocol</span>
                            <span className="text-[var(--color-text-secondary)]">{session.protocol}</span>
                          </div>
                          <div>
                            <span className="block text-[9px] font-bold uppercase tracking-widest mb-0.5 opacity-60">TLS</span>
                            <span className={clsx(session.tlsVersion ? "text-[var(--color-text-secondary)]" : "text-[var(--color-severity-critical)]")}>{session.tlsVersion || 'NONE'}</span>
                          </div>
                          <div className="col-span-2">
                            <span className="block text-[9px] font-bold uppercase tracking-widest mb-0.5 opacity-60">Destination</span>
                            <span className="text-mono text-[var(--color-text-secondary)] truncate block">{session.destHostname || session.destIp}</span>
                          </div>
                        </div>
                      )}
                      <div className="mt-3 flex items-center justify-end text-[11px] font-bold text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors gap-1">
                        Open Session <ChevronRight size={12} />
                      </div>
                    </Link>
                  );
                })}
              </div>
            </motion.div>
          )}

        </div>

      </motion.div>
    </AppShell>
  );
}

/* ── Sub-components ── */

function SectionHeader({ icon: Icon, title, count }: { icon: React.ElementType; title: string; count?: number }) {
  return (
    <div className="flex items-center gap-2 mb-1 border-b border-[var(--color-border-subtle)] pb-4">
      <Icon size={16} className="text-[var(--color-accent)]" />
      <h2 className="text-[12px] uppercase tracking-widest text-[var(--color-text-primary)] font-bold">{title}</h2>
      {count !== undefined && (
        <span className="ml-auto text-[10px] tabular-nums font-bold text-[var(--color-text-secondary)] bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] px-2 py-0.5 rounded">
          {count} Items
        </span>
      )}
    </div>
  );
}

function EvidenceCard({ evidence }: { evidence: Evidence }) {
  return (
    <div className="p-4 sm:p-5 bg-[var(--color-surface-2)] rounded-xl border border-[var(--color-border-subtle)] shadow-sm hover:border-[var(--color-border)] transition-colors">
      <div className="grid grid-cols-2 gap-x-4 gap-y-4 mb-4">
        <EvidenceField label="Session" value={evidence.sessionId} mono link={`/sessions/${evidence.sessionId}`} />
        <EvidenceField label="Timestamp" value={formatDateTime(evidence.timestamp)} />
        <EvidenceField label="Source IP" value={evidence.sourceIp} mono />
        <EvidenceField label="Destination" value={`${evidence.destHostname || evidence.destIp}`} mono />
        <EvidenceField label="Packets Analysed" value={evidence.packets.toString()} mono />
        <EvidenceField label="Observed IOC" value={evidence.observed} mono highlight />
      </div>
      <div className="flex items-center gap-2 pt-4 border-t border-[var(--color-border-subtle)]">
        <Link
          href={`/sessions/${evidence.sessionId}`}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-bold text-[var(--color-accent)] bg-[var(--color-accent-dim)] rounded-md border border-[var(--color-accent)]/20 hover:bg-[var(--color-accent)]/15 transition-colors"
        >
          Inspect PCAP Session <ChevronRight size={12} />
        </Link>
      </div>
    </div>
  );
}

function EvidenceField({ label, value, mono, highlight, link }: {
  label: string; value: string; mono?: boolean; highlight?: boolean; link?: string;
}) {
  const content = (
    <span className={clsx(
      'text-[12px] block truncate',
      mono && 'text-mono',
      highlight ? 'text-[var(--color-severity-high)] font-bold' : 'text-[var(--color-text-primary)] font-semibold',
      link && 'text-[var(--color-accent)] hover:underline cursor-pointer',
    )} title={value}>
      {value}
    </span>
  );
  return (
    <div className="flex flex-col gap-1">
      <div className="text-[9px] uppercase tracking-widest font-bold text-[var(--color-text-dim)]">{label}</div>
      {link ? <Link href={link}>{content}</Link> : content}
    </div>
  );
}
