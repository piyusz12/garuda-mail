'use client';

import { use, useState } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Network, Shield, Lock, FileText, Clock,
  ChevronRight, AlertTriangle, Brain, Eye, Layers,
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
        <div className="flex flex-col items-center justify-center py-20">
          <Network size={48} className="text-[var(--color-text-dim)] mb-4" />
          <h2 className="text-lg font-semibold mb-2">Session not found</h2>
          <p className="text-[13px] text-[var(--color-text-muted)] mb-4">No session with ID &quot;{id}&quot; exists.</p>
          <Link href="/sessions" className="text-[13px] text-[var(--color-accent)] hover:underline">← Back to Sessions</Link>
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

  return (
    <AppShell title={session.id} description={`${session.protocol} session — ${session.destHostname || session.destIp}`}>
      <motion.div initial="initial" animate="animate" className="space-y-5">

        {/* Back nav */}
        <motion.div {...fadeUp}>
          <Link href="/sessions" className="inline-flex items-center gap-1.5 text-[12px] text-[var(--color-text-muted)] hover:text-[var(--color-accent)] transition-colors">
            <ArrowLeft size={14} /> Back to Sessions
          </Link>
        </motion.div>

        {/* Session Header */}
        <motion.div {...fadeUp} className="card p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-[var(--color-surface-3)] border border-[var(--color-border)] flex items-center justify-center">
                <Network size={22} className="text-[var(--color-accent)]" />
              </div>
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <h2 className="text-xl font-bold text-mono text-[var(--color-text-primary)]">{session.id}</h2>
                  <SeverityBadge severity={session.risk} size="sm" />
                </div>
                <p className="text-[13px] text-[var(--color-text-muted)]">
                  {session.protocol} • {session.sourceIp}:{session.sourcePort} → {session.destHostname || session.destIp}:{session.destPort}
                </p>
              </div>
            </div>
            <RiskScore score={session.riskScore} size="md" />
          </div>

          {/* Metadata grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mt-5 pt-5 border-t border-[var(--color-border-subtle)]">
            <MetaField label="Protocol" value={session.protocol} />
            <MetaField label="Source" value={`${session.sourceIp}:${session.sourcePort}`} mono />
            <MetaField label="Destination" value={`${session.destIp}:${session.destPort}`} mono />
            <MetaField label="Duration" value={formatDuration(session.duration)} />
            <MetaField label="Packets" value={String(session.packets)} />
            <MetaField label="Bytes" value={formatBytes(session.bytes)} />
            <MetaField label="TLS Version" value={session.tlsVersion || 'None'} mono highlight={!session.tlsVersion} />
            <MetaField label="STARTTLS" value={session.starttls ? 'Yes' : 'No'} />
            <MetaField label="Findings" value={String(findings.length)} highlight={findings.length > 0} />
            <MetaField label="Anomaly Score" value={session.anomalyScore !== null ? String(session.anomalyScore) : 'N/A'} />
            <MetaField label="JA4" value={session.ja4 || 'N/A'} mono small />
            <MetaField label="Timestamp" value={formatDateTime(session.timestamp)} />
          </div>
        </motion.div>

        {/* Tabs */}
        <motion.div {...fadeUp} className="flex items-center gap-1 border-b border-[var(--color-border)]">
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
                'flex items-center gap-1.5 px-4 py-2.5 text-[12px] font-medium border-b-2 transition-colors -mb-px',
                activeTab === tab.id
                  ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                  : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
              )}
            >
              <tab.icon size={14} />
              {tab.label}
              {tab.count > 0 && (
                <span className="text-[10px] tabular-nums bg-[var(--color-surface-3)] px-1.5 py-0.5 rounded">{tab.count}</span>
              )}
            </button>
          ))}
        </motion.div>

        {/* Tab Content */}
        {activeTab === 'timeline' && <TimelineView events={timeline} />}
        {activeTab === 'tls' && <TlsView tls={tls} cert={cert} />}
        {activeTab === 'packets' && <PacketsView packets={packets} />}
        {activeTab === 'findings' && <FindingsView findings={findings} anomalies={anomalies} />}

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
    <motion.div {...fadeUp} className="card p-5">
      <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold mb-4">Session Timeline</div>
      <div className="relative pl-6">
        <div className="absolute left-[9px] top-2 bottom-2 w-px bg-[var(--color-border)]" />
        {events.map((event, i) => (
          <div key={i} className="relative flex items-start gap-4 pb-4 last:pb-0 group">
            <div
              className="absolute left-[-15px] top-1.5 w-[7px] h-[7px] rounded-full border-2 bg-[var(--color-surface-0)] z-10 group-hover:scale-125 transition-transform"
              style={{ borderColor: typeColors[event.type] || 'var(--color-text-dim)' }}
            />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[11px] text-mono text-[var(--color-text-dim)] tabular-nums">{formatPreciseTimestamp(event.timestamp)}</span>
                <span className="text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded font-semibold" style={{ color: typeColors[event.type], backgroundColor: `${typeColors[event.type]}15` }}>
                  {event.type}
                </span>
              </div>
              <div className="text-[13px] font-medium text-[var(--color-text-primary)]">{event.event}</div>
              <div className="text-[12px] text-[var(--color-text-muted)] mt-0.5">{event.detail}</div>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

/* ── TLS View ── */
function TlsView({ tls, cert }: { tls: TlsAnalysis | null; cert: any }) {
  if (!tls) {
    return (
      <motion.div {...fadeUp} className="card p-10 text-center">
        <Lock size={32} className="text-[var(--color-severity-critical)] mx-auto mb-3" />
        <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">No TLS Encryption</h3>
        <p className="text-[13px] text-[var(--color-text-muted)]">This session did not negotiate TLS. Data was transmitted in plaintext.</p>
      </motion.div>
    );
  }

  return (
    <motion.div {...fadeUp} className="space-y-4">
      <div className="card p-5">
        <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold mb-4">Cryptographic Analysis</div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <TlsField label="TLS Version" value={tls.version} status={tls.policyStatus} />
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
          <div className="mt-4 pt-4 border-t border-[var(--color-border-subtle)]">
            <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] mb-2">Extensions</div>
            <div className="flex flex-wrap gap-1.5">
              {tls.extensions.map(ext => (
                <span key={ext} className="text-[10px] text-mono text-[var(--color-text-muted)] bg-[var(--color-surface-3)] px-2 py-0.5 rounded">{ext}</span>
              ))}
            </div>
          </div>
        )}
      </div>
      {cert && (
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">Certificate</div>
            <Link href={`/certificates/${cert.id}`} className="text-[11px] text-[var(--color-accent)] hover:underline">View Details →</Link>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <MetaField label="Subject" value={cert.subject} mono />
            <MetaField label="Issuer" value={cert.issuer} />
            <MetaField label="Algorithm" value={cert.algorithm} mono />
            <MetaField label="Key" value={`${cert.keyType} ${cert.keySize}-bit`} />
            <MetaField label="Expires" value={formatDateTime(cert.validUntil)} highlight={cert.daysRemaining <= 30} />
            <MetaField label="Status" value={cert.status.toUpperCase()} highlight={cert.status !== 'valid'} />
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
      <motion.div {...fadeUp} className="card p-10 text-center">
        <Layers size={32} className="text-[var(--color-text-dim)] mx-auto mb-3" />
        <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">No Packet Data Available</h3>
        <p className="text-[13px] text-[var(--color-text-muted)]">Detailed packet records are available for the primary analyzed session.</p>
      </motion.div>
    );
  }

  return (
    <motion.div {...fadeUp} className="card overflow-hidden">
      <table className="w-full">
        <thead>
          <tr className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] bg-[var(--color-surface-2)]">
            <th className="text-left px-4 py-3 font-medium">#</th>
            <th className="text-left px-4 py-3 font-medium">Time</th>
            <th className="text-left px-4 py-3 font-medium">Source</th>
            <th className="text-left px-4 py-3 font-medium">Destination</th>
            <th className="text-left px-4 py-3 font-medium">Protocol</th>
            <th className="text-right px-4 py-3 font-medium">Length</th>
            <th className="text-left px-4 py-3 font-medium">Flags</th>
            <th className="text-left px-4 py-3 font-medium">Summary</th>
          </tr>
        </thead>
        <tbody>
          {packets.map(pkt => (
            <tr
              key={pkt.number}
              className={clsx(
                'border-t border-[var(--color-border-subtle)] hover:bg-[var(--color-surface-2)] transition-colors cursor-pointer',
                expanded === pkt.number && 'bg-[var(--color-surface-2)]'
              )}
              onClick={() => setExpanded(expanded === pkt.number ? null : pkt.number)}
            >
              <td className="px-4 py-2.5 text-[11px] text-mono text-[var(--color-accent)] font-medium">{pkt.number}</td>
              <td className="px-4 py-2.5 text-[11px] text-mono text-[var(--color-text-dim)] tabular-nums">{formatPreciseTimestamp(pkt.timestamp)}</td>
              <td className="px-4 py-2.5 text-[11px] text-mono text-[var(--color-text-secondary)]">{pkt.sourceIp}:{pkt.sourcePort}</td>
              <td className="px-4 py-2.5 text-[11px] text-mono text-[var(--color-text-secondary)]">{pkt.destIp}:{pkt.destPort}</td>
              <td className="px-4 py-2.5">
                <span className={clsx('text-[10px] text-mono font-semibold px-1.5 py-0.5 rounded', {
                  'text-blue-400 bg-blue-400/10': pkt.protocol === 'SMTP',
                  'text-cyan-400 bg-cyan-400/10': pkt.protocol === 'TLS',
                  'text-gray-400 bg-gray-400/10': pkt.protocol === 'TCP',
                })}>{pkt.protocol}</span>
              </td>
              <td className="px-4 py-2.5 text-[11px] text-mono text-[var(--color-text-muted)] text-right tabular-nums">{pkt.length}</td>
              <td className="px-4 py-2.5 text-[10px] text-mono text-[var(--color-text-dim)]">{pkt.flags}</td>
              <td className="px-4 py-2.5 text-[11px] text-[var(--color-text-secondary)] truncate max-w-[300px]">{pkt.summary}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </motion.div>
  );
}

/* ── Findings View ── */
function FindingsView({ findings, anomalies }: { findings: any[]; anomalies: any[] }) {
  return (
    <motion.div {...fadeUp} className="space-y-4">
      {findings.length > 0 && (
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield size={14} className="text-[var(--color-severity-critical)]" />
            <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">Security Findings</span>
            <span className="text-[10px] tabular-nums bg-[var(--color-surface-3)] px-1.5 py-0.5 rounded text-[var(--color-text-dim)]">{findings.length}</span>
          </div>
          <div className="space-y-2">
            {findings.map(f => (
              <Link key={f.id} href={`/findings/${f.id}`} className="flex items-center justify-between p-3 rounded-md bg-[var(--color-surface-2)] hover:bg-[var(--color-surface-3)] transition-colors group">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={f.severity} size="xs" />
                  <div>
                    <div className="text-[13px] font-medium text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] transition-colors">{f.title}</div>
                    <div className="text-[11px] text-[var(--color-text-dim)]">{f.id} • {f.category}</div>
                  </div>
                </div>
                <ChevronRight size={14} className="text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)]" />
              </Link>
            ))}
          </div>
        </div>
      )}
      {anomalies.length > 0 && (
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Brain size={14} className="text-[var(--color-accent)]" />
            <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-semibold">AI Anomalies</span>
          </div>
          <div className="space-y-2">
            {anomalies.map(a => (
              <div key={a.id} className="p-3 rounded-md bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[12px] text-mono text-[var(--color-text-dim)]">{a.id}</span>
                  <span className="text-[12px] font-bold tabular-nums" style={{ color: a.anomalyScore >= 70 ? 'var(--color-severity-critical)' : a.anomalyScore >= 40 ? 'var(--color-severity-high)' : 'var(--color-severity-low)' }}>
                    Score: {a.anomalyScore}
                  </span>
                </div>
                <div className="text-[11px] text-[var(--color-text-muted)]">
                  {a.reasoningSignals.map((s: string, i: number) => (
                    <span key={i} className="block">• {s}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      {findings.length === 0 && anomalies.length === 0 && (
        <div className="card p-10 text-center">
          <Shield size={32} className="text-[var(--color-severity-healthy)] mx-auto mb-3" />
          <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">No Issues Detected</h3>
          <p className="text-[13px] text-[var(--color-text-muted)]">No security findings or anomalies were identified in this session.</p>
        </div>
      )}
    </motion.div>
  );
}

/* ── Helpers ── */

function MetaField({ label, value, mono, highlight, small }: { label: string; value: string; mono?: boolean; highlight?: boolean; small?: boolean }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] mb-0.5">{label}</div>
      <div className={clsx(
        mono && 'text-mono',
        small ? 'text-[10px]' : 'text-[12px]',
        highlight ? 'text-[var(--color-severity-critical)] font-semibold' : 'text-[var(--color-text-secondary)]',
      )}>{value}</div>
    </div>
  );
}

function TlsField({ label, value, mono, status, good, statusColor }: {
  label: string; value: string; mono?: boolean; status?: string; good?: boolean; statusColor?: string;
}) {
  return (
    <div className="p-3 bg-[var(--color-surface-2)] rounded-md border border-[var(--color-border-subtle)]">
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] mb-1">{label}</div>
      <div className={clsx('text-[13px] font-semibold', mono && 'text-mono', 'text-[var(--color-text-primary)]')}>
        {value}
      </div>
      {status && (
        <div className="text-[10px] mt-1 uppercase tracking-wider font-semibold" style={{ color: getPolicyStatusColor(status) }}>
          {getPolicyStatusLabel(status)}
        </div>
      )}
      {good !== undefined && (
        <div className={clsx('text-[10px] mt-1 uppercase tracking-wider font-semibold', good ? 'text-[var(--color-severity-healthy)]' : 'text-[var(--color-severity-critical)]')}>
          {good ? '✓ Secure' : '✗ Not Secure'}
        </div>
      )}
      {statusColor && (
        <div className="text-[10px] mt-1 uppercase tracking-wider font-semibold" style={{ color: statusColor }}>
          ■
        </div>
      )}
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
