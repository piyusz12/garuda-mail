'use client';

import { useState, useMemo, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Network, Filter, ArrowUpDown, ExternalLink, ShieldCheck, AlertTriangle } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { mockSessions } from '@/lib/mock/data';
import Link from 'next/link';
import clsx from 'clsx';

type SortField = 'timestamp' | 'protocol' | 'riskScore' | 'destHostname' | 'tlsVersion';
type SortDir = 'asc' | 'desc';

const PAGE_SIZE = 50;
const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };
const stagger = { animate: { transition: { staggerChildren: 0.05 } } };

export default function SessionsPage() {
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('riskScore');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(0);

  const animateRows = page === 0;

  const protocols = ['all', 'SMTP', 'IMAP', 'POP3'];
  const risks = ['all', 'critical', 'high', 'medium', 'low'];

  const filteredSessions = useMemo(() => {
    let sessions = [...mockSessions];
    if (protocolFilter !== 'all') sessions = sessions.filter(s => s.protocol === protocolFilter);
    if (riskFilter !== 'all') sessions = sessions.filter(s => s.risk === riskFilter);
    sessions.sort((a, b) => {
      const aVal = a[sortField] ?? '';
      const bVal = b[sortField] ?? '';
      if (typeof aVal === 'number' && typeof bVal === 'number') {
        return sortDir === 'asc' ? aVal - bVal : bVal - aVal;
      }
      return sortDir === 'asc'
        ? String(aVal).localeCompare(String(bVal))
        : String(bVal).localeCompare(String(aVal));
    });
    return sessions;
  }, [protocolFilter, riskFilter, sortField, sortDir]);

  useEffect(() => {
    setPage(0);
  }, [protocolFilter, riskFilter, sortField, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filteredSessions.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages - 1);
  const visibleSessions = useMemo(
    () => filteredSessions.slice(currentPage * PAGE_SIZE, currentPage * PAGE_SIZE + PAGE_SIZE),
    [filteredSessions, currentPage],
  );

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const plainTextCount = mockSessions.filter(s => !s.tlsVersion).length;

  return (
    <AppShell title="Network Sessions" description="Network telemetry and cryptographic session analysis">
      <motion.div initial="initial" animate="animate" variants={stagger} className="max-w-[1400px] mx-auto pb-12 space-y-5">

        {/* ── Header ── */}
        <motion.div variants={fadeUp} className="card p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-sm rounded-xl relative overflow-hidden">
          <div className="z-10">
            <h1 className="text-[22px] font-bold text-[var(--color-text-primary)] tracking-tight flex items-center gap-2">
              <Network size={22} className="text-[var(--color-accent)]" />
              Network Forensics
            </h1>
            <p className="text-[13px] text-[var(--color-text-muted)] mt-1 ml-8">Network telemetry and cryptographic session analysis.</p>
          </div>

          <div className="flex items-center gap-3 z-10 overflow-x-auto hide-scrollbar">
            <div className="flex flex-col p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] min-w-[120px]">
              <span className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-1">Total Sessions</span>
              <span className="text-[20px] font-bold text-[var(--color-text-primary)] tabular-nums leading-none">{mockSessions.length}</span>
            </div>
            <div className="flex flex-col p-3 bg-[var(--color-severity-critical-bg)] rounded-lg border border-[var(--color-severity-critical)]/30 min-w-[120px]">
              <span className="text-[10px] uppercase tracking-widest text-[var(--color-severity-critical)] font-bold mb-1">Plaintext</span>
              <span className="text-[20px] font-bold text-[var(--color-severity-critical)] tabular-nums leading-none">{plainTextCount}</span>
            </div>
          </div>

          <div className="absolute -top-32 -right-10 w-64 h-64 bg-[var(--color-accent)] opacity-5 rounded-full blur-3xl pointer-events-none" />
        </motion.div>

        {/* ── Toolbar ── */}
        <motion.div variants={fadeUp} className="flex flex-col md:flex-row items-center gap-4 bg-[var(--color-surface-2)] p-2.5 rounded-xl border border-[var(--color-border-subtle)] shadow-sm">
          <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto hide-scrollbar">
            <div className="flex items-center gap-2 pl-2 pr-3 border-r border-[var(--color-border-subtle)] shrink-0">
              <Filter size={14} className="text-[var(--color-text-dim)]" />
              <span className="text-[11px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold">Triage</span>
            </div>

            {/* Protocol Segment */}
            <div className="flex bg-[var(--color-surface-1)] border border-[var(--color-border-subtle)] rounded-lg p-1 shrink-0">
              {protocols.map(p => (
                <button
                  key={p}
                  onClick={() => setProtocolFilter(p)}
                  className={clsx(
                    'px-3 py-1.5 text-[11px] font-bold rounded-md transition-all',
                    protocolFilter === p
                      ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] shadow-sm'
                      : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
                  )}
                >
                  {p === 'all' ? 'All Protocols' : p}
                </button>
              ))}
            </div>

            {/* Risk Segment */}
            <div className="flex bg-[var(--color-surface-1)] border border-[var(--color-border-subtle)] rounded-lg p-1 shrink-0">
              {risks.map(r => (
                <button
                  key={r}
                  onClick={() => setRiskFilter(r)}
                  className={clsx(
                    'px-3 py-1.5 text-[11px] font-bold rounded-md transition-all capitalize',
                    riskFilter === r
                      ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] shadow-sm'
                      : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
                  )}
                >
                  {r === 'all' ? 'All Risk' : r}
                </button>
              ))}
            </div>
          </div>

          <div className="ml-auto text-[11px] font-bold text-[var(--color-text-dim)] px-2 whitespace-nowrap">
            {visibleSessions.length} of {filteredSessions.length} (Page {currentPage + 1}/{totalPages})
          </div>
        </motion.div>

        {/* ── Data Grid ── */}
        <motion.div variants={fadeUp} className="card overflow-hidden bg-[var(--color-surface-1)] border-[var(--color-border)] shadow-sm rounded-xl">
          <div className="overflow-x-auto hide-scrollbar">
            <table className="w-full text-left min-w-[900px]">
              <thead>
                <tr className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] bg-[var(--color-surface-2)] border-b border-[var(--color-border-subtle)]">
                  <SortHeader label="Session" field="timestamp" currentField={sortField} currentDir={sortDir} onSort={toggleSort} />
                  <SortHeader label="Protocol" field="protocol" currentField={sortField} currentDir={sortDir} onSort={toggleSort} />
                  <th className="px-4 py-3.5 font-bold">Source IP:Port</th>
                  <SortHeader label="Destination" field="destHostname" currentField={sortField} currentDir={sortDir} onSort={toggleSort} />
                  <SortHeader label="TLS Layer" field="tlsVersion" currentField={sortField} currentDir={sortDir} onSort={toggleSort} />
                  <th className="text-center px-4 py-3.5 font-bold">STARTTLS</th>
                  <th className="text-center px-4 py-3.5 font-bold">Alerts</th>
                  <th className="text-center px-4 py-3.5 font-bold">Anomaly</th>
                  <SortHeader label="Risk" field="riskScore" currentField={sortField} currentDir={sortDir} onSort={toggleSort} className="text-center" />
                  <th className="text-center px-4 py-3.5 font-bold">Forensics</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-subtle)]">
                {visibleSessions.map((session, i) => {
                  const isHealthyTls = session.tlsVersion === 'TLS 1.3' || session.tlsVersion === 'TLS 1.2';
                  const isWeakTls = session.tlsVersion === 'TLS 1.1' || session.tlsVersion === 'TLS 1.0';

                  return (
                    <motion.tr
                      key={session.id}
                      initial={animateRows ? { opacity: 0, x: -4 } : false}
                      animate={{ opacity: 1, x: 0 }}
                      transition={animateRows ? { delay: Math.min(i * 0.02, 0.4) } : undefined}
                      className="hover:bg-[var(--color-surface-2)] transition-colors group cursor-pointer"
                      onClick={() => window.location.href = `/sessions/${session.id}`}
                    >
                      <td className="px-4 py-3">
                        <div className="text-[12px] text-mono font-bold text-[var(--color-accent)] group-hover:underline">
                          {session.id}
                        </div>
                        <div className="text-[10px] text-mono text-[var(--color-text-dim)]">{formatTimestamp(session.timestamp)}</div>
                      </td>
                      <td className="px-4 py-3">
                        <ProtocolBadge protocol={session.protocol} />
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[12px] text-mono font-medium text-[var(--color-text-secondary)]">{session.sourceIp}:{session.sourcePort}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-[12px] text-mono font-bold text-[var(--color-text-primary)]">{session.destHostname || session.destIp}</div>
                        <div className="text-[10px] text-mono text-[var(--color-text-dim)]">{session.destIp}:{session.destPort}</div>
                      </td>
                      <td className="px-4 py-3">
                        {session.tlsVersion ? (
                          <div className={clsx(
                            "inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px] text-mono font-bold",
                            isHealthyTls ? "bg-[var(--color-severity-healthy)]/10 text-[var(--color-severity-healthy)] border-[var(--color-severity-healthy)]/30" :
                            isWeakTls ? "bg-[rgba(245,158,11,0.1)] text-[var(--color-severity-high)] border-[var(--color-severity-high)]/30" :
                            "bg-[var(--color-surface-3)] text-[var(--color-text-secondary)] border-[var(--color-border-subtle)]"
                          )}>
                            {isHealthyTls && <ShieldCheck size={10} />}
                            {isWeakTls && <AlertTriangle size={10} />}
                            {session.tlsVersion}
                          </div>
                        ) : (
                          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border bg-[var(--color-severity-critical-bg)] text-[var(--color-severity-critical)] border-[var(--color-severity-critical)]/30 text-[11px] text-mono font-bold">
                            NONE
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {session.starttls ? (
                          <span className="inline-block text-[11px] text-[var(--color-severity-healthy)] bg-[var(--color-severity-healthy)]/10 px-1.5 rounded border border-[var(--color-severity-healthy)]/30">YES</span>
                        ) : (
                          <span className="text-[11px] text-[var(--color-text-dim)]">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {session.findingsCount > 0 ? (
                           <span className="inline-flex items-center justify-center min-w-[20px] h-[20px] text-[11px] font-bold bg-[var(--color-severity-critical-bg)] text-[var(--color-severity-critical)] border border-[var(--color-severity-critical)]/30 rounded-md">
                            {session.findingsCount}
                           </span>
                        ) : (
                          <span className="text-[11px] text-[var(--color-text-dim)]">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {session.anomalyScore !== null ? (
                          <AnomalyDot score={session.anomalyScore} />
                        ) : (
                          <span className="text-[11px] text-[var(--color-text-dim)]">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center">
                        <SeverityBadge severity={session.risk} size="xs" />
                      </td>
                      <td className="px-4 py-3 text-center">
                        <div className="inline-flex items-center justify-center w-7 h-7 rounded-md text-[var(--color-text-muted)] group-hover:text-[var(--color-accent)] group-hover:bg-[var(--color-surface-3)] transition-colors">
                          <ExternalLink size={14} />
                        </div>
                      </td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-4 px-4 py-4 border-t border-[var(--color-border-subtle)] bg-[var(--color-surface-2)]">
              <button
                onClick={(e) => { e.stopPropagation(); setPage(p => Math.max(0, p - 1)); }}
                disabled={currentPage === 0}
                className="px-4 py-1.5 text-[11px] font-bold rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors disabled:opacity-40 disabled:pointer-events-none active:scale-95 shadow-sm"
              >
                ← Prev
              </button>
              <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums font-bold">
                Page {currentPage + 1} of {totalPages}
              </span>
              <button
                onClick={(e) => { e.stopPropagation(); setPage(p => Math.min(totalPages - 1, p + 1)); }}
                disabled={currentPage >= totalPages - 1}
                className="px-4 py-1.5 text-[11px] font-bold rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-1)] text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors disabled:opacity-40 disabled:pointer-events-none active:scale-95 shadow-sm"
              >
                Next →
              </button>
            </div>
          )}
        </motion.div>
      </motion.div>
    </AppShell>
  );
}

function SortHeader({ label, field, currentField, currentDir, onSort, className }: {
  label: string; field: SortField; currentField: SortField; currentDir: SortDir;
  onSort: (f: SortField) => void; className?: string;
}) {
  const active = currentField === field;
  return (
    <th
      className={clsx('px-4 py-3.5 font-bold cursor-pointer hover:text-[var(--color-text-primary)] transition-colors select-none text-left group', className)}
      onClick={() => onSort(field)}
    >
      <div className={clsx("flex items-center gap-1", className?.includes('text-center') && 'justify-center')}>
        <span>{label}</span>
        <ArrowUpDown size={12} className={active ? 'text-[var(--color-accent)]' : 'opacity-30 group-hover:opacity-60 transition-opacity'} />
      </div>
    </th>
  );
}

function ProtocolBadge({ protocol }: { protocol: string }) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 text-[11px] font-bold rounded border bg-[var(--color-surface-3)] border-[var(--color-border-subtle)] text-[var(--color-text-secondary)] text-mono">
      {protocol}
    </span>
  );
}

function AnomalyDot({ score }: { score: number }) {
  const color = score >= 70 ? 'var(--color-severity-critical)' : score >= 40 ? 'var(--color-severity-high)' : 'var(--color-severity-low)';
  return (
    <div className="flex items-center justify-center gap-1.5" title={`Anomaly score: ${score}`}>
      <div className="w-2.5 h-2.5 rounded-full shadow-sm" style={{ backgroundColor: color }} />
      <span className="text-[12px] font-bold tabular-nums text-[var(--color-text-primary)]">{score}</span>
    </div>
  );
}

function formatTimestamp(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}
