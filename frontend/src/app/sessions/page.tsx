'use client';

import { useState, useMemo, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Network, Filter, ArrowUpDown, ExternalLink } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { mockSessions } from '@/lib/mock/data';
import Link from 'next/link';
import clsx from 'clsx';

type SortField = 'timestamp' | 'protocol' | 'riskScore' | 'destHostname' | 'tlsVersion';
type SortDir = 'asc' | 'desc';

const PAGE_SIZE = 50;

export default function SessionsPage() {
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('riskScore');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(0);
  // Per-row mount animations on hundreds of rows cause jank; only animate the
  // first screenful and cap the stagger delay.
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

  // Reset to first page whenever filters/sort change.
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

  return (
    <AppShell title="Sessions" description={`${mockSessions.length} reconstructed email protocol sessions`}>
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
        {/* Filters */}
        <div className="card p-4 flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-[var(--color-text-muted)]" />
            <span className="text-[11px] uppercase tracking-wider text-[var(--color-text-muted)] font-medium">Filters</span>
          </div>
          <div className="flex gap-1">
            {protocols.map(p => (
              <button
                key={p}
                onClick={() => setProtocolFilter(p)}
                className={clsx(
                  'px-3 py-1.5 text-[11px] font-medium rounded-md transition-colors',
                  protocolFilter === p
                    ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[rgba(56,189,248,0.15)]'
                    : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent'
                )}
              >
                {p === 'all' ? 'All Protocols' : p}
              </button>
            ))}
          </div>
          <div className="w-px h-5 bg-[var(--color-border)]" />
          <div className="flex gap-1">
            {risks.map(r => (
              <button
                key={r}
                onClick={() => setRiskFilter(r)}
                className={clsx(
                  'px-3 py-1.5 text-[11px] font-medium rounded-md transition-colors capitalize',
                  riskFilter === r
                    ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[rgba(56,189,248,0.15)]'
                    : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent'
                )}
              >
                {r === 'all' ? 'All Risk' : r}
              </button>
            ))}
          </div>
          <div className="ml-auto text-[11px] text-[var(--color-text-dim)]">
            {visibleSessions.length} of {filteredSessions.length} sessions (page {currentPage + 1}/{totalPages})
          </div>
        </div>

        {/* Table */}
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] bg-[var(--color-surface-2)]">
                  <SortHeader label="Session" field="timestamp" currentField={sortField} currentDir={sortDir} onSort={toggleSort} />
                  <SortHeader label="Protocol" field="protocol" currentField={sortField} currentDir={sortDir} onSort={toggleSort} />
                  <th className="text-left px-4 py-3 font-medium">Source</th>
                  <SortHeader label="Destination" field="destHostname" currentField={sortField} currentDir={sortDir} onSort={toggleSort} />
                  <SortHeader label="TLS" field="tlsVersion" currentField={sortField} currentDir={sortDir} onSort={toggleSort} />
                  <th className="text-center px-4 py-3 font-medium">STARTTLS</th>
                  <th className="text-center px-4 py-3 font-medium">Findings</th>
                  <th className="text-center px-4 py-3 font-medium">Anomaly</th>
                  <SortHeader label="Risk" field="riskScore" currentField={sortField} currentDir={sortDir} onSort={toggleSort} className="text-center" />
                  <th className="text-center px-4 py-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visibleSessions.map((session, i) => (
                  <motion.tr
                    key={session.id}
                    initial={animateRows ? { opacity: 0, x: -8 } : false}
                    animate={{ opacity: 1, x: 0 }}
                    transition={animateRows ? { delay: Math.min(i * 0.02, 0.3) } : undefined}
                    className="border-t border-[var(--color-border-subtle)] hover:bg-[var(--color-surface-2)] transition-colors"
                  >
                    <td className="px-4 py-3">
                      <Link href={`/sessions/${session.id}`} className="text-[12px] text-mono text-[var(--color-accent)] hover:underline font-medium">
                        {session.id}
                      </Link>
                      <div className="text-[10px] text-[var(--color-text-dim)]">{formatTimestamp(session.timestamp)}</div>
                    </td>
                    <td className="px-4 py-3">
                      <ProtocolBadge protocol={session.protocol} />
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-[12px] text-mono text-[var(--color-text-secondary)]">{session.sourceIp}:{session.sourcePort}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-[12px] text-mono text-[var(--color-text-primary)]">{session.destHostname || session.destIp}</div>
                      <div className="text-[10px] text-mono text-[var(--color-text-dim)]">{session.destIp}:{session.destPort}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={clsx(
                        'text-[12px] text-mono',
                        !session.tlsVersion ? 'text-[var(--color-severity-critical)] font-semibold' :
                        session.tlsVersion === 'TLS 1.0' || session.tlsVersion === 'TLS 1.1' ? 'text-[var(--color-severity-high)]' :
                        'text-[var(--color-text-secondary)]'
                      )}>
                        {session.tlsVersion || 'NONE'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      {session.starttls ? (
                        <span className="text-[11px] text-[var(--color-severity-healthy)]">✓</span>
                      ) : (
                        <span className="text-[11px] text-[var(--color-text-dim)]">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className={clsx(
                        'text-[12px] font-semibold tabular-nums',
                        session.findingsCount > 0 ? 'text-[var(--color-severity-high)]' : 'text-[var(--color-text-dim)]'
                      )}>
                        {session.findingsCount}
                      </span>
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
                      <Link
                        href={`/sessions/${session.id}`}
                        className="inline-flex items-center justify-center w-7 h-7 rounded-md text-[var(--color-text-muted)] hover:text-[var(--color-accent)] hover:bg-[var(--color-surface-3)] transition-colors"
                      >
                        <ExternalLink size={13} />
                      </Link>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-3 px-4 py-3 border-t border-[var(--color-border-subtle)]">
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={currentPage === 0}
                className="px-3 py-1 text-[11px] font-medium rounded-md border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] transition-colors disabled:opacity-40 disabled:pointer-events-none"
              >
                ← Prev
              </button>
              <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums">
                Page {currentPage + 1} of {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={currentPage >= totalPages - 1}
                className="px-3 py-1 text-[11px] font-medium rounded-md border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] transition-colors disabled:opacity-40 disabled:pointer-events-none"
              >
                Next →
              </button>
            </div>
          )}
        </div>
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
      className={clsx('px-4 py-3 font-medium cursor-pointer hover:text-[var(--color-text-secondary)] transition-colors select-none text-left', className)}
      onClick={() => onSort(field)}
    >
      <div className="flex items-center gap-1">
        <span>{label}</span>
        <ArrowUpDown size={10} className={active ? 'text-[var(--color-accent)]' : 'opacity-30'} />
      </div>
    </th>
  );
}

function ProtocolBadge({ protocol }: { protocol: string }) {
  const color = {
    SMTP: 'text-blue-400 bg-blue-400/10 border-blue-400/15',
    IMAP: 'text-purple-400 bg-purple-400/10 border-purple-400/15',
    POP3: 'text-amber-400 bg-amber-400/10 border-amber-400/15',
    UNKNOWN: 'text-gray-400 bg-gray-400/10 border-gray-400/15',
  }[protocol] || 'text-gray-400 bg-gray-400/10 border-gray-400/15';

  return (
    <span className={clsx('inline-flex items-center px-2 py-0.5 text-[10px] font-semibold rounded border text-mono', color)}>
      {protocol}
    </span>
  );
}

function AnomalyDot({ score }: { score: number }) {
  const color = score >= 70 ? 'var(--color-severity-critical)' : score >= 40 ? 'var(--color-severity-high)' : 'var(--color-severity-low)';
  return (
    <div className="flex items-center justify-center gap-1.5" title={`Anomaly score: ${score}`}>
      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
      <span className="text-[11px] tabular-nums text-[var(--color-text-secondary)]">{score}</span>
    </div>
  );
}

function formatTimestamp(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}
