'use client';

import { use } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Shield, Brain, AlertTriangle, ExternalLink,
  Copy, CheckCircle, FileText, Bookmark, ChevronRight,
  Info, Target, Layers, ClipboardCheck,
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, StatusBadge, RiskScore } from '@/components/ui/shared';
import { mockFindings, mockSessions } from '@/lib/mock/data';
import { formatDateTime, formatPreciseTimestamp } from '@/lib/formatters';
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

  if (!finding) {
    return (
      <AppShell title="Finding Not Found" description="The requested finding does not exist">
        <div className="flex flex-col items-center justify-center py-20">
          <AlertTriangle size={48} className="text-[var(--color-text-dim)] mb-4" />
          <h2 className="text-lg font-semibold text-[var(--color-text-primary)] mb-2">Finding not found</h2>
          <p className="text-[13px] text-[var(--color-text-muted)] mb-4">No finding with ID "{id}" exists in the current analysis.</p>
          <Link href="/findings" className="text-[13px] text-[var(--color-accent)] hover:underline">← Back to Findings</Link>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell title={finding.id} description={finding.title}>
      <motion.div initial="initial" animate="animate" className="space-y-5 max-w-[1100px]">

        {/* ── Back nav ── */}
        <motion.div {...fadeUp}>
          <Link href="/findings" className="inline-flex items-center gap-1.5 text-[12px] text-[var(--color-text-muted)] hover:text-[var(--color-accent)] transition-colors">
            <ArrowLeft size={14} /> Back to Findings
          </Link>
        </motion.div>

        {/* ── Finding Header ── */}
        <motion.div {...fadeUp} className="card p-6">
          <div className="flex items-start gap-4">
            <div className="flex flex-col items-center gap-2">
              <SeverityBadge severity={finding.severity} size="md" />
              {finding.detectionSource === 'ai_anomaly' ? (
                <Brain size={16} className="text-[var(--color-accent)]" />
              ) : (
                <Shield size={16} className="text-[var(--color-text-muted)]" />
              )}
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[12px] text-mono text-[var(--color-text-dim)]">{finding.id}</span>
                {finding.ruleId && (
                  <span className="text-[10px] text-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] px-1.5 py-0.5 rounded">{finding.ruleId}</span>
                )}
                <StatusBadge status={finding.status} />
              </div>
              <h2 className="text-xl font-bold text-[var(--color-text-primary)] mb-2">{finding.title}</h2>
              <p className="text-[13px] text-[var(--color-text-secondary)] leading-relaxed">{finding.description}</p>
              <div className="flex items-center gap-4 mt-3 text-[11px] text-[var(--color-text-dim)]">
                <span>Category: <span className="text-[var(--color-text-secondary)]">{finding.category}</span></span>
                <span>•</span>
                <span>Detection: <span className="text-[var(--color-text-secondary)]">{finding.detectionSource === 'rule_engine' ? 'Deterministic Rule' : finding.detectionSource === 'ai_anomaly' ? 'AI Analysis' : 'Combined'}</span></span>
                <span>•</span>
                <span>Confidence: <span className="font-semibold text-[var(--color-text-primary)]">{finding.confidence}%</span></span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* ── Two Column: Why It Matters + Risk ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Why It Matters */}
          <motion.div {...fadeUp} className="lg:col-span-2 card p-5">
            <SectionHeader icon={Info} title="Why It Matters" />
            <p className="text-[13px] text-[var(--color-text-secondary)] leading-relaxed mt-3">{finding.whyItMatters}</p>
          </motion.div>

          {/* Confidence & Risk */}
          <motion.div {...fadeUp} className="card p-5">
            <SectionHeader icon={Target} title="Confidence" />
            <div className="flex flex-col items-center mt-4">
              <div className="relative w-20 h-20">
                <svg width={80} height={80} className="-rotate-90">
                  <circle cx={40} cy={40} r={34} fill="none" stroke="var(--color-surface-3)" strokeWidth={4} />
                  <circle
                    cx={40} cy={40} r={34} fill="none"
                    stroke={finding.confidence >= 90 ? 'var(--color-severity-healthy)' : finding.confidence >= 70 ? 'var(--color-accent)' : 'var(--color-severity-high)'}
                    strokeWidth={4}
                    strokeDasharray={2 * Math.PI * 34}
                    strokeDashoffset={2 * Math.PI * 34 * (1 - finding.confidence / 100)}
                    strokeLinecap="round"
                    className="transition-all duration-700"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-lg font-bold tabular-nums text-[var(--color-text-primary)]">{finding.confidence}%</span>
                </div>
              </div>
              <span className="text-[11px] text-[var(--color-text-muted)] mt-2 uppercase tracking-wider">
                {finding.detectionSource === 'rule_engine' ? 'Deterministic' : 'AI-Derived'}
              </span>
            </div>
          </motion.div>
        </div>

        {/* ── Evidence ── */}
        <motion.div {...fadeUp} className="card p-5">
          <SectionHeader icon={FileText} title="Evidence" count={finding.evidence.length} />
          <div className="space-y-3 mt-4">
            {finding.evidence.map((ev, i) => (
              <EvidenceCard key={i} evidence={ev} />
            ))}
          </div>
        </motion.div>

        {/* ── Technical Details ── */}
        <motion.div {...fadeUp} className="card p-5">
          <SectionHeader icon={Layers} title="Technical Details" />
          <div className="mt-3 p-4 bg-[var(--color-surface-2)] rounded-md border border-[var(--color-border-subtle)]">
            <p className="text-[13px] text-mono text-[var(--color-text-secondary)] leading-relaxed whitespace-pre-wrap">{finding.technicalDetails}</p>
          </div>
        </motion.div>

        {/* ── Two Column: Remediation + Standards ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Remediation */}
          <motion.div {...fadeUp} className="card p-5">
            <div className="flex items-center justify-between mb-3">
              <SectionHeader icon={CheckCircle} title="Remediation" />
              <SeverityBadge severity={finding.remediationPriority} size="xs" />
            </div>
            <div className="p-4 bg-[var(--color-surface-2)] rounded-md border border-[var(--color-border-subtle)] mb-4">
              <p className="text-[13px] text-[var(--color-text-secondary)] leading-relaxed">{finding.remediation}</p>
            </div>
            <div className="mb-3">
              <span className="text-[11px] text-[var(--color-text-dim)] uppercase tracking-wider">Affected Assets</span>
              <div className="flex flex-wrap gap-1.5 mt-1.5">
                {finding.affectedAssets.map(asset => (
                  <span key={asset} className="text-[11px] text-mono text-[var(--color-accent)] bg-[var(--color-accent-dim)] px-2 py-0.5 rounded border border-[rgba(56,189,248,0.12)]">
                    {asset}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex items-center gap-2 pt-3 border-t border-[var(--color-border-subtle)]">
              <button className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium text-[var(--color-text-secondary)] bg-[var(--color-surface-3)] rounded-md hover:bg-[var(--color-surface-4)] transition-colors">
                <Copy size={12} /> Copy Recommendation
              </button>
              <button className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium text-[var(--color-text-secondary)] bg-[var(--color-surface-3)] rounded-md hover:bg-[var(--color-surface-4)] transition-colors">
                <Bookmark size={12} /> Mark Reviewed
              </button>
            </div>
          </motion.div>

          {/* Standards Mapping */}
          <motion.div {...fadeUp} className="card p-5">
            <SectionHeader icon={ClipboardCheck} title="Standards Mapping" count={finding.standardsMapping.length} />
            {finding.standardsMapping.length > 0 ? (
              <div className="space-y-3 mt-3">
                {finding.standardsMapping.map((mapping, i) => (
                  <div key={i} className="p-3 bg-[var(--color-surface-2)] rounded-md border border-[var(--color-border-subtle)]">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">{mapping.standard}</span>
                      <span className="text-[10px] text-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] px-1.5 py-0.5 rounded">{mapping.severity}</span>
                    </div>
                    <div className="text-[11px] text-[var(--color-text-muted)] mb-1">{mapping.reference}</div>
                    <div className="text-[12px] text-[var(--color-text-secondary)]">{mapping.recommendation}</div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-[12px] text-[var(--color-text-dim)] mt-3">No standards mapping available for this finding.</p>
            )}
          </motion.div>
        </div>

        {/* ── Related Sessions ── */}
        <motion.div {...fadeUp} className="card p-5">
          <SectionHeader icon={ExternalLink} title="Related Sessions" count={finding.relatedSessionIds.length} />
          <div className="space-y-2 mt-3">
            {finding.relatedSessionIds.map(sessionId => {
              const session = mockSessions.find(s => s.id === sessionId);
              return (
                <Link
                  key={sessionId}
                  href={`/sessions/${sessionId}`}
                  className="flex items-center justify-between p-3 rounded-md bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] transition-colors group"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-[12px] text-mono text-[var(--color-accent)] font-medium">{sessionId}</span>
                    {session && (
                      <>
                        <span className="text-[11px] text-[var(--color-text-muted)]">{session.protocol}</span>
                        <span className="text-[11px] text-mono text-[var(--color-text-dim)]">{session.destHostname || session.destIp}</span>
                        <span className="text-[11px] text-mono text-[var(--color-text-dim)]">{session.tlsVersion || 'No TLS'}</span>
                      </>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {session && <SeverityBadge severity={session.risk} size="xs" />}
                    <ChevronRight size={14} className="text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors" />
                  </div>
                </Link>
              );
            })}
          </div>
        </motion.div>

      </motion.div>
    </AppShell>
  );
}

/* ── Sub-components ── */

function SectionHeader({ icon: Icon, title, count }: { icon: React.ElementType; title: string; count?: number }) {
  return (
    <div className="flex items-center gap-2">
      <Icon size={14} className="text-[var(--color-accent)]" />
      <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">{title}</span>
      {count !== undefined && (
        <span className="text-[10px] tabular-nums text-[var(--color-text-dim)] bg-[var(--color-surface-3)] px-1.5 py-0.5 rounded">{count}</span>
      )}
    </div>
  );
}

function EvidenceCard({ evidence }: { evidence: Evidence }) {
  return (
    <div className="p-4 bg-[var(--color-surface-2)] rounded-md border border-[var(--color-border-subtle)]">
      <div className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-2">
        <EvidenceField label="Session" value={evidence.sessionId} mono link={`/sessions/${evidence.sessionId}`} />
        <EvidenceField label="Packets" value={evidence.packets} mono />
        <EvidenceField label="Observed" value={evidence.observed} mono highlight />
        <EvidenceField label="Source" value={evidence.sourceIp} mono />
        <EvidenceField label="Destination" value={`${evidence.destHostname || evidence.destIp}`} mono />
        <EvidenceField label="Timestamp" value={formatDateTime(evidence.timestamp)} />
      </div>
      <div className="flex items-center gap-2 mt-3 pt-3 border-t border-[var(--color-border-subtle)]">
        <Link
          href={`/sessions/${evidence.sessionId}`}
          className="text-[11px] text-[var(--color-accent)] hover:underline"
        >
          View Session →
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
      'text-[12px]',
      mono && 'text-mono',
      highlight ? 'text-[var(--color-severity-high)] font-semibold' : 'text-[var(--color-text-secondary)]',
      link && 'text-[var(--color-accent)] hover:underline cursor-pointer',
    )}>
      {value}
    </span>
  );
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] mb-0.5">{label}</div>
      {link ? <Link href={link}>{content}</Link> : content}
    </div>
  );
}
