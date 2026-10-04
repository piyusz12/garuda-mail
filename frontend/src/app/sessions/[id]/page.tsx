'use client';

import { use, useState } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Network, Shield, Lock, FileText, Clock,
  ChevronRight, AlertTriangle, Brain, Layers, Server, Activity, ShieldAlert, ShieldCheck, Info
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, RiskScore } from '@/components/ui/shared';
import { mockSessions, mockFindings, mockAnomalies, mockCertificates } from '@/lib/mock/data';
import { mockSessionTimeline, mockSessionTls, mockPackets } from '@/lib/mock/details';
import { formatDuration, formatBytes, formatPreciseTimestamp, formatDateTime, getPolicyStatusLabel, getPolicyStatusColor } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';
import type { SessionTimelineEvent, PacketRecord, TlsAnalysis } from '@/types';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function SessionDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const session = mockSessions.find(s => s.id === id);
  const [activeTab, setActiveTab] = useState<'timeline' | 'tls' | 'packets' | 'findings'>('timeline');

  if (!session) {
    return (
      <AppShell title="Session Not Found">
        <div className="flex flex-col items-center justify-center py-32">
          <Network size={48} className="text-[var(--color-text-dim)] mb-6" />
          <h2 className="text-xl font-bold text-[var(--color-text-primary)] mb-2 tracking-tight">Record Not Found</h2>
          <p className="text-[14px] text-[var(--color-text-muted)] mb-6">No network session with ID <span className="font-mono text-[var(--color-text-secondary)]">{id}</span> exists.</p>
          <Link href="/sessions" className="text-[13px] font-medium text-[var(--color-text-primary)] bg-[var(--color-surface-2)] border border-[var(--color-border)] hover:bg-[var(--color-surface-3)] transition-colors px-4 py-2 rounded-lg shadow-sm">
            Return to Sessions
          </Link>
        </div>
      </AppShell>
    );
  }

  const findings = mockFindings.filter(f => f.relatedSessionIds.includes(id));
  const anomalies = mockAnomalies.filter(a => a.sessionId === id);
  const cert = mockCertificates.find(c => c.relatedSessionIds.includes(id));
  const tls = id === 'SMTP-0192' ? mockSessionTls : session.tlsVersion ? buildBasicTls(session) : null;
  const timeline = id === 'SMTP-0192' ? mockSessionTimeline : buildBasicTimeline(session);
  const packets = id === 'SMTP-0192' ? mockPackets : [];

  const isHealthyTls = session.tlsVersion === 'TLS 1.3' || session.tlsVersion === 'TLS 1.2';
  const isWeakTls = session.tlsVersion === 'TLS 1.1' || session.tlsVersion === 'TLS 1.0';

  const levelColor = session.risk === 'critical' ? 'var(--color-severity-critical)' :
                     session.risk === 'high' ? 'var(--color-severity-high)' :
                     session.risk === 'medium' ? 'var(--color-severity-medium)' :
                     session.risk === 'low' ? 'var(--color-severity-low)' : 'var(--color-text-dim)';

  const levelBg = session.risk === 'critical' ? 'var(--color-severity-critical-bg)' :
                  session.risk === 'high' ? 'rgba(245, 158, 11, 0.05)' :
                  session.risk === 'medium' ? 'rgba(234, 179, 8, 0.05)' :
                  session.risk === 'low' ? 'rgba(56, 189, 248, 0.05)' : 'var(--color-surface-2)';

  const levelBorder = session.risk === 'critical' ? 'rgba(239, 68, 68, 0.3)' :
                      session.risk === 'high' ? 'rgba(245, 158, 11, 0.3)' :
                      session.risk === 'medium' ? 'rgba(234, 179, 8, 0.3)' :
                      session.risk === 'low' ? 'rgba(56, 189, 248, 0.3)' : 'var(--color-border-subtle)';

  const SecIcon = session.risk === 'critical' ? ShieldAlert :
                  session.risk === 'high' ? AlertTriangle :
                  session.risk === 'medium' ? AlertTriangle :
                  session.risk === 'low' ? Info : ShieldCheck;

  return (
    <AppShell title={session.id} description={`${session.protocol} session — ${session.destHostname || session.destIp}`}>
      <motion.div initial="initial" animate="animate" className="flex flex-col lg:flex-row gap-6 max-w-[1400px] mx-auto pb-12">

        {/* ── Left Column - Main Content (~65%) ── */}
        <div className="flex-1 flex flex-col min-w-0 space-y-4">

          {/* Back nav */}
          <motion.div {...fadeUp} className="flex items-center justify-between mb-1 px-1">
            <Link href="/sessions" className="inline-flex items-center gap-1.5 text-[13px] font-medium text-[var(--color-text-muted)] hover:text-[var(--color-accent)] transition-colors group">
              <ArrowLeft size={16} className="transition-transform group-hover:-translate-x-1" /> Back to Sessions
            </Link>
          </motion.div>

          {/* Session Header */}
          <motion.div {...fadeUp} className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
            <div className="flex items-start justify-between gap-5 border-b border-[var(--color-border-subtle)] pb-6 mb-6">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] flex items-center justify-center shrink-0">
                  <Network size={22} className="text-[var(--color-accent)]" />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-1.5 flex-wrap">
                    <h2 className="text-[22px] font-bold text-mono text-[var(--color-text-primary)] leading-none">{session.id}</h2>
                    <span className="inline-flex items-center px-2 py-0.5 text-[11px] font-bold rounded border bg-[var(--color-surface-3)] border-[var(--color-border-subtle)] text-[var(--color-text-secondary)] text-mono">
                      {session.protocol}
                    </span>
                  </div>
                  <p className="text-[14px] text-[var(--color-text-muted)] font-mono">
                    <span className="text-[var(--color-text-secondary)]">{session.sourceIp}:{session.sourcePort}</span>
                    <span className="mx-2 text-[var(--color-border)]">→</span>
                    <span className="text-[var(--color-text-secondary)]">{session.destHostname || session.destIp}:{session.destPort}</span>
                  </p>
                </div>
              </div>
            </div>

            {/* Metadata grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetaField label="Duration" value={formatDuration(session.duration)} />
              <MetaField label="Packets" value={String(session.packets)} mono />
              <MetaField label="Bytes" value={formatBytes(session.bytes)} mono />
              <MetaField label="Timestamp" value={formatDateTime(session.timestamp)} />
            </div>
          </motion.div>

          {/* Tabs */}
          <motion.div {...fadeUp} className="flex items-center gap-1 border-b border-[var(--color-border)] mt-2">
            {[
              { id: 'timeline' as const, label: 'Timeline', icon: Clock, count: timeline.length },
              { id: 'tls' as const, label: 'TLS Analysis', icon: Lock, count: tls ? 1 : 0 },
              { id: 'packets' as const, label: 'Packets', icon: Layers, count: packets.length },
              { id: 'findings' as const, label: 'Findings', icon: AlertTriangle, count: findings.length },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'flex items-center gap-2 px-4 py-3 text-[12px] font-bold transition-colors -mb-px border-b-2',
                  activeTab === tab.id
                    ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                    : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border)]'
                )}
              >
                <tab.icon size={14} />
                {tab.label}
                {tab.count > 0 && (
                  <span className={clsx("text-[10px] tabular-nums px-1.5 py-0.5 rounded border", activeTab === tab.id ? "bg-[var(--color-accent-dim)] border-[var(--color-accent)]/20 text-[var(--color-accent)]" : "bg-[var(--color-surface-3)] border-[var(--color-border-subtle)] text-[var(--color-text-dim)]")}>{tab.count}</span>
                )}
              </button>
            ))}
          </motion.div>

          {/* Tab Content */}
          <div className="pt-2">
            {activeTab === 'timeline' && <TimelineView events={timeline} />}
            {activeTab === 'tls' && <TlsView tls={tls} cert={cert} session={session} />}
            {activeTab === 'packets' && <PacketsView packets={packets} />}
            {activeTab === 'findings' && <FindingsView findings={findings} anomalies={anomalies} />}
          </div>

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
                  <h2 className="text-[11px] font-bold tracking-widest uppercase" style={{ color: levelColor }}>Session Assessment</h2>
                </div>

                <div className="flex flex-col gap-5 relative z-10">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-[40px] font-bold tracking-tighter leading-none mb-1 drop-shadow-sm" style={{ color: levelColor }}>
                        {session.riskScore}
                        <span className="text-[16px] text-[var(--color-text-dim)] font-medium ml-1">/ 100</span>
                      </div>
                      <div className="text-[12px] font-bold text-[var(--color-text-primary)] tracking-wider mt-1 uppercase">
                        Overall Risk Score
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      <div className={clsx(
                        "flex items-center gap-1.5 px-3 py-1.5 border rounded-lg shadow-sm text-[11px] font-bold uppercase tracking-widest",
                        session.risk === 'critical' ? 'bg-[var(--color-severity-critical-bg)] border-[var(--color-severity-critical)]/30 text-[var(--color-severity-critical)]' :
                        session.risk === 'high' ? 'bg-[rgba(245,158,11,0.1)] border-[var(--color-severity-high)]/30 text-[var(--color-severity-high)]' :
                        session.risk === 'medium' ? 'bg-[rgba(234,179,8,0.1)] border-[var(--color-severity-medium)]/30 text-[var(--color-severity-medium)]' :
                        'bg-[var(--color-surface-1)] border-[var(--color-border)] text-[var(--color-text-secondary)]'
                      )}>
                        {session.risk}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Cryptographic Posture Highlights */}
              <div className="p-6 space-y-4 relative z-10">
                <div className="text-[11px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-2">Cryptographic Posture</div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="flex flex-col gap-1 p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] shadow-sm">
                    <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold flex items-center gap-1"><Lock size={10}/> TLS Layer</div>
                    {session.tlsVersion ? (
                      <div className={clsx("text-[14px] text-mono font-bold leading-none mt-1", isHealthyTls ? "text-[var(--color-severity-healthy)]" : isWeakTls ? "text-[var(--color-severity-high)]" : "text-[var(--color-text-primary)]")}>{session.tlsVersion}</div>
                    ) : (
                      <div className="text-[14px] text-mono font-bold leading-none mt-1 text-[var(--color-severity-critical)]">NONE</div>
                    )}
                  </div>

                  <div className="flex flex-col gap-1 p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] shadow-sm">
                    <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold flex items-center gap-1"><ShieldCheck size={10}/> STARTTLS</div>
                    <div className={clsx("text-[14px] font-bold leading-none mt-1", session.starttls ? "text-[var(--color-severity-healthy)]" : "text-[var(--color-text-dim)]")}>{session.starttls ? 'Upgraded' : 'N/A'}</div>
                  </div>

                  <div className="col-span-2 flex flex-col gap-1.5 p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] shadow-sm">
                    <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold">JA4 Fingerprint</div>
                    <div className="text-[13px] text-mono font-bold text-[var(--color-text-secondary)]">{session.ja4 || 'N/A'}</div>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-4 border-t border-[var(--color-border-subtle)]">
                   <div className="flex items-center gap-2">
                     <AlertTriangle size={14} className={findings.length > 0 ? "text-[var(--color-severity-high)]" : "text-[var(--color-text-dim)]"} />
                     <span className="text-[11px] font-bold text-[var(--color-text-secondary)]">{findings.length} Findings</span>
                   </div>
                   <div className="flex items-center gap-2">
                     <Brain size={14} className={session.anomalyScore ? "text-[var(--color-accent)]" : "text-[var(--color-text-dim)]"} />
                     <span className="text-[11px] font-bold text-[var(--color-text-secondary)]">
                       {session.anomalyScore ? `Anomaly: ${session.anomalyScore}` : 'No Anomalies'}
                     </span>
                   </div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>

      </motion.div>
    </AppShell>
  );
}

/* ── Timeline View ── */
function TimelineView({ events }: { events: SessionTimelineEvent[] }) {
  const typeColors: Record<string, string> = {
    tcp: 'var(--color-text-muted)',
    smtp: 'var(--color-severity-low)',
    imap: 'var(--color-severity-low)',
    pop3: 'var(--color-severity-low)',
    tls: 'var(--color-accent)',
    certificate: 'var(--color-severity-high)',
    anomaly: 'var(--color-severity-critical)',
    data: 'var(--color-severity-healthy)',
  };

  return (
    <motion.div {...fadeUp} className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
      <div className="text-[12px] uppercase tracking-widest text-[var(--color-text-primary)] font-bold mb-6 border-b border-[var(--color-border-subtle)] pb-4">Session Timeline</div>
      <div className="relative pl-7">
        <div className="absolute left-[13px] top-3 bottom-3 w-px bg-[var(--color-border-subtle)]" />
        {events.map((event, i) => (
          <div key={i} className="relative flex items-start gap-5 pb-6 last:pb-0 group">
            <div
              className="absolute left-[-19px] top-1.5 w-[9px] h-[9px] rounded-full border-[2.5px] bg-[var(--color-surface-1)] z-10 group-hover:scale-125 transition-transform shadow-sm"
              style={{ borderColor: typeColors[event.type] || 'var(--color-text-dim)' }}
            />
            <div className="flex-1 min-w-0 bg-[var(--color-surface-2)] p-4 rounded-lg border border-[var(--color-border-subtle)] group-hover:border-[var(--color-border)] transition-colors">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[12px] font-bold text-[var(--color-text-primary)]">{event.event}</span>
                <span className="text-[11px] text-mono font-bold text-[var(--color-text-dim)] bg-[var(--color-surface-1)] px-2 py-0.5 rounded border border-[var(--color-border-subtle)]">{formatPreciseTimestamp(event.timestamp)}</span>
              </div>
              <div className="text-[13px] text-[var(--color-text-secondary)] font-mono mb-2">{event.detail}</div>
              <span className="inline-block text-[9px] uppercase tracking-widest px-2 py-1 rounded font-bold border" style={{ color: typeColors[event.type], backgroundColor: `${typeColors[event.type]}15`, borderColor: `${typeColors[event.type]}30` }}>
                {event.type}
              </span>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

/* ── TLS View ── */
function TlsView({ tls, cert, session }: { tls: TlsAnalysis | null; cert: any; session: any }) {
  if (!tls) {
    return (
      <motion.div {...fadeUp} className="card p-12 text-center border border-[var(--color-severity-critical)]/30 bg-[var(--color-severity-critical-bg)] shadow-sm rounded-xl">
        <Lock size={36} className="text-[var(--color-severity-critical)] mx-auto mb-4" />
        <h3 className="text-[16px] font-bold text-[var(--color-severity-critical)] mb-2">No TLS Encryption</h3>
        <p className="text-[14px] text-[var(--color-text-secondary)]">This session did not negotiate TLS. All data was transmitted in plaintext.</p>
      </motion.div>
    );
  }

  const isHealthyTls = session.tlsVersion === 'TLS 1.3' || session.tlsVersion === 'TLS 1.2';
  const isWeakTls = session.tlsVersion === 'TLS 1.1' || session.tlsVersion === 'TLS 1.0';

  return (
    <motion.div {...fadeUp} className="space-y-4">
      <div className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
        <div className="text-[12px] uppercase tracking-widest text-[var(--color-text-primary)] font-bold mb-6 border-b border-[var(--color-border-subtle)] pb-4">Cryptographic Analysis</div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          <TlsField label="TLS Version" value={tls.version} status={tls.policyStatus} isWeak={isWeakTls} isHealthy={isHealthyTls} />
          <TlsField label="Cipher Suite" value={tls.cipherSuite} mono />
          <TlsField label="Key Exchange" value={tls.keyExchange} />
          <TlsField label="Authentication" value={tls.authentication} />
          <TlsField label="Encryption" value={tls.encryption} />
          <TlsField label="Hash" value={tls.hash} />
          <TlsField label="Forward Secrecy" value={tls.forwardSecrecy ? 'OBSERVED' : 'NOT OBSERVED'} good={tls.forwardSecrecy} />
          <TlsField label="SNI" value={tls.sni || 'N/A'} mono />
          <TlsField label="Policy Status" value={getPolicyStatusLabel(tls.policyStatus)} statusColor={getPolicyStatusColor(tls.policyStatus)} />
        </div>
        {tls.extensions.length > 0 && (
          <div className="mt-6 pt-5 border-t border-[var(--color-border-subtle)]">
            <div className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-3">Extensions</div>
            <div className="flex flex-wrap gap-2">
              {tls.extensions.map(ext => (
                <span key={ext} className="text-[11px] text-mono font-bold text-[var(--color-text-secondary)] bg-[var(--color-surface-2)] px-2.5 py-1 rounded border border-[var(--color-border-subtle)]">{ext}</span>
              ))}
            </div>
          </div>
        )}
      </div>
      {cert && (
        <div className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
          <div className="flex items-center justify-between mb-6 border-b border-[var(--color-border-subtle)] pb-4">
            <div className="text-[12px] uppercase tracking-widest text-[var(--color-text-primary)] font-bold">Certificate Details</div>
            <Link href={`/certificates/${cert.id}`} className="text-[11px] font-bold text-[var(--color-accent)] hover:underline flex items-center gap-1">View Full Cert <ChevronRight size={12}/></Link>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
            <TlsField label="Subject" value={cert.subject} mono />
            <TlsField label="Issuer" value={cert.issuer} />
            <TlsField label="Algorithm" value={cert.algorithm} mono />
            <TlsField label="Key" value={`${cert.keyType} ${cert.keySize}-bit`} mono />
            <TlsField label="Expires" value={formatDateTime(cert.validUntil)} highlight={cert.daysRemaining <= 30} />
            <TlsField label="Status" value={cert.status.toUpperCase()} highlight={cert.status !== 'valid'} good={cert.status === 'valid'} />
          </div>
        </div>
      )}
    </motion.div>
  );
}

/* ── Packets View ── */
function PacketsView({ packets }: { packets: PacketRecord[] }) {
  const [expanded, setExpanded] = useState<number | null>(null);

  if (packets.length === 0) {
    return (
      <motion.div {...fadeUp} className="card p-12 text-center border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
        <Layers size={36} className="text-[var(--color-text-dim)] mx-auto mb-4" />
        <h3 className="text-[16px] font-bold text-[var(--color-text-primary)] mb-2">No Packet Data Available</h3>
        <p className="text-[14px] text-[var(--color-text-muted)]">Detailed packet records are available for the primary analyzed session.</p>
      </motion.div>
    );
  }

  return (
    <motion.div {...fadeUp} className="card overflow-hidden border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
      <div className="overflow-x-auto hide-scrollbar">
        <table className="w-full text-left min-w-[700px]">
          <thead>
            <tr className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] bg-[var(--color-surface-2)] border-b border-[var(--color-border-subtle)]">
              <th className="px-4 py-3 font-bold">#</th>
              <th className="px-4 py-3 font-bold">Time</th>
              <th className="px-4 py-3 font-bold">Source</th>
              <th className="px-4 py-3 font-bold">Destination</th>
              <th className="px-4 py-3 font-bold">Protocol</th>
              <th className="text-right px-4 py-3 font-bold">Length</th>
              <th className="px-4 py-3 font-bold">Flags</th>
              <th className="px-4 py-3 font-bold">Summary</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border-subtle)]">
            {packets.map(pkt => (
              <tr
                key={pkt.number}
                className={clsx(
                  'hover:bg-[var(--color-surface-2)] transition-colors cursor-pointer',
                  expanded === pkt.number && 'bg-[var(--color-surface-2)]'
                )}
                onClick={() => setExpanded(expanded === pkt.number ? null : pkt.number)}
              >
                <td className="px-4 py-2.5 text-[11px] text-mono font-bold text-[var(--color-accent)]">{pkt.number}</td>
                <td className="px-4 py-2.5 text-[11px] text-mono text-[var(--color-text-dim)] tabular-nums">{formatPreciseTimestamp(pkt.timestamp)}</td>
                <td className="px-4 py-2.5 text-[11px] text-mono font-medium text-[var(--color-text-secondary)]">{pkt.sourceIp}:{pkt.sourcePort}</td>
                <td className="px-4 py-2.5 text-[11px] text-mono font-medium text-[var(--color-text-secondary)]">{pkt.destIp}:{pkt.destPort}</td>
                <td className="px-4 py-2.5">
                  <span className={clsx('text-[10px] text-mono font-bold px-2 py-0.5 rounded border', {
                    'text-blue-400 bg-blue-400/10 border-blue-400/20': pkt.protocol === 'SMTP',
                    'text-cyan-400 bg-cyan-400/10 border-cyan-400/20': pkt.protocol === 'TLS',
                    'text-gray-400 bg-gray-400/10 border-gray-400/20': pkt.protocol === 'TCP',
                  })}>{pkt.protocol}</span>
                </td>
                <td className="px-4 py-2.5 text-[11px] text-mono text-[var(--color-text-muted)] text-right tabular-nums">{pkt.length}</td>
                <td className="px-4 py-2.5 text-[10px] text-mono text-[var(--color-text-dim)]">{pkt.flags}</td>
                <td className="px-4 py-2.5 text-[12px] text-[var(--color-text-secondary)] font-mono truncate max-w-[200px] xl:max-w-[300px]">{pkt.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.div>
  );
}

/* ── Findings View ── */
function FindingsView({ findings, anomalies }: { findings: any[]; anomalies: any[] }) {
  return (
    <motion.div {...fadeUp} className="space-y-4">
      {findings.length > 0 && (
        <div className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
          <div className="flex items-center gap-2 mb-6 border-b border-[var(--color-border-subtle)] pb-4">
            <ShieldAlert size={16} className="text-[var(--color-severity-critical)]" />
            <h2 className="text-[12px] uppercase tracking-widest text-[var(--color-text-primary)] font-bold">Security Findings</h2>
            <span className="ml-auto text-[10px] tabular-nums font-bold text-[var(--color-severity-critical)] bg-[var(--color-severity-critical-bg)] border border-[var(--color-severity-critical)]/30 px-2 py-0.5 rounded">{findings.length} Found</span>
          </div>
          <div className="space-y-3">
            {findings.map(f => (
              <Link key={f.id} href={`/findings/${f.id}`} className="flex items-center justify-between p-4 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] hover:bg-[var(--color-surface-3)] transition-all group shadow-sm">
                <div className="flex items-center gap-4">
                  <SeverityBadge severity={f.severity} size="sm" />
                  <div>
                    <div className="text-[14px] font-bold text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] transition-colors mb-0.5">{f.title}</div>
                    <div className="text-[11px] text-mono text-[var(--color-text-dim)] flex gap-2">
                       <span className="bg-[var(--color-surface-1)] px-1.5 rounded">{f.id}</span>
                       <span>•</span>
                       <span>{f.category}</span>
                    </div>
                  </div>
                </div>
                <ChevronRight size={14} className="text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors" />
              </Link>
            ))}
          </div>
        </div>
      )}
      {anomalies.length > 0 && (
        <div className="card p-6 border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
          <div className="flex items-center gap-2 mb-6 border-b border-[var(--color-border-subtle)] pb-4">
            <Brain size={16} className="text-[var(--color-accent)]" />
            <h2 className="text-[12px] uppercase tracking-widest text-[var(--color-text-primary)] font-bold">AI Anomalies</h2>
          </div>
          <div className="space-y-3">
            {anomalies.map(a => (
              <div key={a.id} className="p-4 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] shadow-sm">
                <div className="flex items-center justify-between mb-3 border-b border-[var(--color-border-subtle)] pb-3">
                  <span className="text-[12px] font-bold text-mono text-[var(--color-text-secondary)]">{a.id}</span>
                  <span className="text-[12px] font-bold tabular-nums px-2 py-0.5 rounded border" style={{
                    color: a.anomalyScore >= 70 ? 'var(--color-severity-critical)' : a.anomalyScore >= 40 ? 'var(--color-severity-high)' : 'var(--color-severity-low)',
                    backgroundColor: a.anomalyScore >= 70 ? 'var(--color-severity-critical-bg)' : a.anomalyScore >= 40 ? 'rgba(245,158,11,0.1)' : 'rgba(56, 189, 248, 0.1)',
                    borderColor: a.anomalyScore >= 70 ? 'rgba(239, 68, 68, 0.3)' : a.anomalyScore >= 40 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(56, 189, 248, 0.3)'
                  }}>
                    Score: {a.anomalyScore}
                  </span>
                </div>
                <div className="text-[12px] font-mono text-[var(--color-text-muted)] space-y-1.5">
                  {a.reasoningSignals.map((s: string, i: number) => (
                    <div key={i} className="flex gap-2"><span className="text-[var(--color-accent)]">→</span> <span>{s}</span></div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      {findings.length === 0 && anomalies.length === 0 && (
        <div className="card p-12 text-center border border-[var(--color-border)] bg-[var(--color-surface-1)] shadow-sm rounded-xl">
          <ShieldCheck size={36} className="text-[var(--color-severity-healthy)] mx-auto mb-4" />
          <h3 className="text-[16px] font-bold text-[var(--color-text-primary)] mb-2">No Issues Detected</h3>
          <p className="text-[14px] text-[var(--color-text-muted)]">No security findings or anomalies were identified in this session.</p>
        </div>
      )}
    </motion.div>
  );
}

/* ── Helpers ── */

function MetaField({ label, value, mono, highlight, small }: { label: string; value: string; mono?: boolean; highlight?: boolean; small?: boolean }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold">{label}</div>
      <div className={clsx(
        mono && 'text-mono',
        small ? 'text-[11px]' : 'text-[13px]',
        highlight ? 'text-[var(--color-severity-critical)] font-bold' : 'text-[var(--color-text-primary)] font-semibold',
      )}>{value}</div>
    </div>
  );
}

function TlsField({ label, value, mono, status, good, isWeak, isHealthy, highlight, statusColor }: {
  label: string; value: string; mono?: boolean; status?: string; good?: boolean; isWeak?: boolean; isHealthy?: boolean; highlight?: boolean; statusColor?: string;
}) {
  return (
    <div className="p-4 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] shadow-sm flex flex-col justify-between">
      <div>
        <div className="text-[9px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-1.5">{label}</div>
        <div className={clsx('text-[13px] font-bold leading-tight', mono && 'text-mono', highlight ? 'text-[var(--color-severity-critical)]' : isWeak ? 'text-[var(--color-severity-high)]' : isHealthy ? 'text-[var(--color-severity-healthy)]' : 'text-[var(--color-text-primary)]')}>
          {value}
        </div>
      </div>
      <div className="mt-3 flex flex-col gap-1">
        {status && (
          <div className="text-[10px] uppercase tracking-widest font-bold" style={{ color: getPolicyStatusColor(status) }}>
            {getPolicyStatusLabel(status)}
          </div>
        )}
        {good !== undefined && (
          <div className={clsx('text-[10px] uppercase tracking-widest font-bold flex items-center gap-1', good ? 'text-[var(--color-severity-healthy)]' : 'text-[var(--color-severity-critical)]')}>
            {good ? '✓ Secure' : '✗ Not Secure'}
          </div>
        )}
        {statusColor && (
          <div className="w-full h-1 mt-1 rounded-full" style={{ backgroundColor: statusColor }} />
        )}
      </div>
    </div>
  );
}

function buildBasicTls(session: any): TlsAnalysis {
  const isWeak = session.tlsVersion === 'TLS 1.0' || session.tlsVersion === 'TLS 1.1';
  return {
    version: session.tlsVersion, versionNumeric: 0x0303,
    cipherSuite: isWeak ? 'TLS_RSA_WITH_AES_128_CBC_SHA' : 'ECDHE-RSA-AES256-GCM-SHA384',
    keyExchange: isWeak ? 'RSA' : 'ECDHE (P-256)', authentication: 'RSA',
    encryption: isWeak ? 'AES-128-CBC' : 'AES-256-GCM', hash: isWeak ? 'SHA-1' : 'SHA-384',
    forwardSecrecy: !isWeak, sni: session.destHostname, alpn: [],
    extensions: ['server_name', 'supported_groups', 'signature_algorithms'],
    policyStatus: session.tlsVersion === 'TLS 1.0' ? 'insecure' : session.tlsVersion === 'TLS 1.1' ? 'deprecated' : session.tlsVersion === 'TLS 1.3' ? 'compliant' : 'acceptable',
  };
}

function buildBasicTimeline(session: any): SessionTimelineEvent[] {
  const ts = session.timestamp;
  const events: SessionTimelineEvent[] = [
    { timestamp: ts, event: 'TCP Established', detail: `${session.sourceIp}:${session.sourcePort} → ${session.destIp}:${session.destPort}`, type: 'tcp' },
    { timestamp: ts, event: `${session.protocol} Greeting`, detail: `Server greeting from ${session.destHostname || session.destIp}`, type: session.protocol.toLowerCase() as any },
  ];
  if (session.starttls) events.push({ timestamp: ts, event: 'STARTTLS', detail: 'STARTTLS upgrade initiated', type: 'tls' });
  if (session.tlsVersion) {
    events.push({ timestamp: ts, event: 'TLS Handshake', detail: `${session.tlsVersion} negotiated`, type: 'tls' });
    events.push({ timestamp: ts, event: 'Encrypted Session', detail: 'Application data exchange', type: 'data' });
  } else {
    events.push({ timestamp: ts, event: 'Plaintext Session', detail: 'No encryption', type: 'data' });
  }
  events.push({ timestamp: ts, event: 'TCP FIN', detail: 'Connection closed', type: 'tcp' });
  return events;
}
