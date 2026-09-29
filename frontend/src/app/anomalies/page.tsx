'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Brain, Fingerprint, AlertTriangle, Shield, Activity,
  Search, ExternalLink, Info, Sparkles, ChevronRight,
  TrendingUp, BarChart2, CheckCircle2, Sliders
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { mockAnomalies, mockSessions } from '@/lib/mock/data';
import { mockJa4Fingerprints } from '@/lib/mock/details';
import { formatDateTime } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';
import type { Anomaly, Ja4Fingerprint } from '@/types';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function AnomaliesPage() {
  const [activeTab, setActiveTab] = useState<'anomalies' | 'ja4'>('anomalies');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(mockAnomalies[0]);

  const filteredJa4 = mockJa4Fingerprints.filter(j =>
    j.fingerprint.toLowerCase().includes(searchTerm.toLowerCase()) ||
    j.rarity.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <AppShell
      title="AI Anomalies & JA4 Fingerprints"
      description="Behavioral outlier detection using unsupervised ensemble models and JA4 cryptographic client fingerprinting"
    >
      <div className="space-y-6">

        {/* ── AI Engine Health & Model Metadata Bar ── */}
        <div className="card p-4 bg-gradient-to-r from-[rgba(56,189,248,0.06)] to-transparent border-[rgba(56,189,248,0.2)] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[rgba(56,189,248,0.12)] border border-[rgba(56,189,248,0.25)] flex items-center justify-center text-[var(--color-accent)]">
              <Brain size={22} />
            </div>
            <div>
              <div className="text-[14px] font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <span>AI Anomaly Inference Engine</span>
                <span className="badge-healthy text-[9px] px-1.5 py-0.5 rounded font-bold uppercase">ACTIVE</span>
              </div>
              <p className="text-[12px] text-[var(--color-text-muted)]">
                Dual-Model Architecture: Isolation Forest (Contamination: 0.05) + Deep Autoencoder (Latent: 16)
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6 text-[11px] text-[var(--color-text-secondary)]">
            <div>
              <span className="text-[var(--color-text-dim)]">Baseline Volume: </span>
              <span className="text-mono font-semibold text-[var(--color-text-primary)]">14,200 sessions</span>
            </div>
            <div>
              <span className="text-[var(--color-text-dim)]">Inference Latency: </span>
              <span className="text-mono font-semibold text-[var(--color-text-primary)]">4.2 ms/flow</span>
            </div>
          </div>
        </div>

        {/* ── Top Metrics ── */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Total Anomalies</span>
              <Brain size={16} className="text-[var(--color-accent)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-text-primary)] tabular-nums">
              {mockAnomalies.length}
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">Deviations exceeding baseline threshold</p>
          </div>

          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>High Severity Outliers</span>
              <AlertTriangle size={16} className="text-[var(--color-severity-critical)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-critical)] tabular-nums">
              {mockAnomalies.filter(a => a.anomalyScore >= 70).length}
            </div>
            <p className="text-[11px] text-[var(--color-severity-critical)] font-medium">Score &gt;= 70/100 threshold</p>
          </div>

          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Unique JA4 Fingerprints</span>
              <Fingerprint size={16} className="text-[var(--color-accent)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-accent)] tabular-nums">
              {mockJa4Fingerprints.length}
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">Distinct client implementations observed</p>
          </div>

          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Rare / Outlier JA4s</span>
              <AlertTriangle size={16} className="text-[var(--color-severity-high)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-high)] tabular-nums">
              {mockJa4Fingerprints.filter(j => j.rarity === 'rare').length}
            </div>
            <p className="text-[11px] text-[var(--color-severity-high)] font-medium">Unusual client TLS configurations</p>
          </div>
        </div>

        {/* ── Tabs Navigation ── */}
        <div className="flex items-center gap-2 border-b border-[var(--color-border)]">
          <button
            onClick={() => setActiveTab('anomalies')}
            className={clsx(
              'px-4 py-2.5 text-[13px] font-medium border-b-2 flex items-center gap-2 transition-colors',
              activeTab === 'anomalies'
                ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
            )}
          >
            <Brain size={16} /> AI Behavioral Anomaly Alerts ({mockAnomalies.length})
          </button>
          <button
            onClick={() => setActiveTab('ja4')}
            className={clsx(
              'px-4 py-2.5 text-[13px] font-medium border-b-2 flex items-center gap-2 transition-colors',
              activeTab === 'ja4'
                ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
            )}
          >
            <Fingerprint size={16} /> JA4 Fingerprint Database ({mockJa4Fingerprints.length})
          </button>
        </div>

        {/* ── TAB 1: AI Anomaly Alerts ── */}
        {activeTab === 'anomalies' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* List of Anomalies (1 col) */}
            <div className="space-y-3">
              {mockAnomalies.map((ano) => (
                <div
                  key={ano.id}
                  onClick={() => setSelectedAnomaly(ano)}
                  className={clsx(
                    'card p-4 cursor-pointer transition-all duration-150',
                    selectedAnomaly?.id === ano.id
                      ? 'border-[var(--color-accent)] bg-[rgba(56,189,248,0.04)] ring-1 ring-[var(--color-accent)]'
                      : 'hover:border-[var(--color-border-hover)]'
                  )}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-mono font-bold text-[13px] text-[var(--color-text-primary)]">
                        {ano.id}
                      </span>
                      <span className="text-[10px] text-mono bg-[var(--color-surface-3)] px-1.5 py-0.5 rounded text-[var(--color-accent)]">
                        {ano.protocol}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={clsx(
                        'text-mono font-bold text-[13px]',
                        ano.anomalyScore >= 70 ? 'text-[var(--color-severity-critical)]' :
                        ano.anomalyScore >= 50 ? 'text-[var(--color-severity-high)]' :
                        'text-[var(--color-severity-medium)]'
                      )}>
                        Score: {ano.anomalyScore}
                      </span>
                    </div>
                  </div>

                  <div className="text-[12px] text-[var(--color-text-secondary)] font-medium mb-2">
                    Linked Session: <span className="text-mono text-[var(--color-accent)]">{ano.sessionId}</span>
                  </div>

                  <div className="flex flex-wrap gap-1 mb-2">
                    {ano.reasoningSignals.slice(0, 2).map((sig, i) => (
                      <span key={i} className="text-[10px] bg-[var(--color-surface-3)] text-[var(--color-text-dim)] px-1.5 py-0.5 rounded truncate max-w-[220px]">
                        {sig}
                      </span>
                    ))}
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-[var(--color-text-dim)] pt-2 border-t border-[var(--color-border-subtle)]">
                    <span>Confidence: {ano.confidence}%</span>
                    <span>{formatDateTime(ano.timestamp)}</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Detailed Explainable AI (XAI) View (2 cols) */}
            <div className="lg:col-span-2">
              {selectedAnomaly ? (
                <div className="card p-6 space-y-6">
                  <div className="flex items-start justify-between pb-4 border-b border-[var(--color-border)]">
                    <div>
                      <div className="flex items-center gap-2.5 mb-1">
                        <h3 className="text-lg font-bold text-[var(--color-text-primary)]">
                          Anomaly Breakdown: {selectedAnomaly.id}
                        </h3>
                        <span className="badge-critical text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                          Score {selectedAnomaly.anomalyScore}/100
                        </span>
                      </div>
                      <p className="text-[12px] text-[var(--color-text-muted)]">
                        Target Session: <Link href={`/sessions/${selectedAnomaly.sessionId}`} className="text-mono text-[var(--color-accent)] hover:underline">{selectedAnomaly.sessionId}</Link> • Protocol: {selectedAnomaly.protocol}
                      </p>
                    </div>

                    <Link
                      href={`/sessions/${selectedAnomaly.sessionId}`}
                      className="btn btn-secondary text-[12px] py-1.5 px-3 flex items-center gap-1.5"
                    >
                      View Forensic Trace <ChevronRight size={14} />
                    </Link>
                  </div>

                  {/* Reasoning Signals List */}
                  <div className="space-y-2">
                    <div className="text-[11px] uppercase font-bold tracking-wider text-[var(--color-text-dim)] flex items-center gap-2">
                      <Sparkles size={14} className="text-[var(--color-accent)]" />
                      Model Reasoning Signals
                    </div>
                    <div className="space-y-1.5">
                      {selectedAnomaly.reasoningSignals.map((signal, idx) => (
                        <div key={idx} className="p-3 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] flex items-start gap-2.5 text-[12px] text-[var(--color-text-primary)]">
                          <CheckCircle2 size={15} className="text-[var(--color-accent)] mt-0.5 flex-shrink-0" />
                          <span>{signal}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Feature Contribution / SHAP Values */}
                  <div className="space-y-3">
                    <div className="text-[11px] uppercase font-bold tracking-wider text-[var(--color-text-dim)] flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <BarChart2 size={14} className="text-[var(--color-accent)]" />
                        Explainable Feature Contributions (SHAP-Style)
                      </div>
                      <span className="text-[10px] text-[var(--color-text-dim)]">Normalized feature weights</span>
                    </div>

                    <div className="space-y-3">
                      {selectedAnomaly.featureContributions.map((fc, i) => (
                        <div key={i} className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-2">
                          <div className="flex items-center justify-between text-[12px]">
                            <span className="font-semibold text-mono text-[var(--color-text-primary)]">{fc.feature}</span>
                            <span className="text-mono font-bold text-[var(--color-accent)]">
                              +{(fc.importance * 100).toFixed(0)}% contribution (val: {fc.value})
                            </span>
                          </div>
                          <div className="h-2 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-[var(--color-accent)] to-[var(--color-severity-critical)] rounded-full"
                              style={{ width: `${fc.importance * 100}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* JA4 Fingerprint association */}
                  {selectedAnomaly.ja4 && (
                    <div className="p-4 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] flex items-center justify-between">
                      <div>
                        <div className="text-[10px] text-[var(--color-text-dim)] uppercase font-bold tracking-wider">Associated JA4 Fingerprint</div>
                        <div className="text-mono text-[12px] text-[var(--color-accent)] mt-0.5">{selectedAnomaly.ja4}</div>
                      </div>
                      <button
                        onClick={() => {
                          setSearchTerm(selectedAnomaly.ja4 || '');
                          setActiveTab('ja4');
                        }}
                        className="btn btn-ghost text-[11px] py-1 px-2 text-[var(--color-text-secondary)]"
                      >
                        Lookup in Database →
                      </button>
                    </div>
                  )}

                </div>
              ) : (
                <div className="card p-12 text-center text-[var(--color-text-muted)]">
                  Select an anomaly from the list to view forensic explanations.
                </div>
              )}
            </div>

          </div>
        )}

        {/* ── TAB 2: JA4 Fingerprint Database ── */}
        {activeTab === 'ja4' && (
          <div className="space-y-4">
            {/* Search */}
            <div className="card p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="relative w-full sm:w-96">
                <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)]" />
                <input
                  type="text"
                  placeholder="Filter by JA4 string or rarity (common, rare)..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-4 py-1.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] placeholder-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
                />
              </div>

              <div className="text-[12px] text-[var(--color-text-muted)]">
                Showing {filteredJa4.length} fingerprints
              </div>
            </div>

            {/* JA4 Anatomy Card */}
            <div className="card p-4 bg-[var(--color-surface-1)] border-[var(--color-border)] text-[12px] space-y-2">
              <div className="font-semibold text-[var(--color-text-primary)] flex items-center gap-1.5">
                <Info size={14} className="text-[var(--color-accent)]" />
                JA4 Cryptographic Client Fingerprinting Standard:
              </div>
              <p className="text-[var(--color-text-muted)] leading-relaxed">
                JA4 fingerprints client TLS hellos: <span className="text-mono text-[var(--color-accent)]">t13d1516h2_8daaf6152771_e5627efa2ab1</span> where <span className="text-mono text-white">t</span> = TCP, <span className="text-mono text-white">13</span> = TLS 1.3, <span className="text-mono text-white">d</span> = SNI specified, <span className="text-mono text-white">15</span> ciphers, <span className="text-mono text-white">16</span> extensions, <span className="text-mono text-white">h2</span> = ALPN HTTP/2, followed by 12-char SHA-256 hashes of ciphers and extensions.
              </p>
            </div>

            {/* Table */}
            <div className="card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-[13px]">
                  <thead>
                    <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-2)] text-[11px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                      <th className="py-3 px-4">JA4 Fingerprint</th>
                      <th className="py-3 px-4">Rarity Rating</th>
                      <th className="py-3 px-4">Frequency</th>
                      <th className="py-3 px-4">First Observed</th>
                      <th className="py-3 px-4">Last Observed</th>
                      <th className="py-3 px-4 text-right">Associated Sessions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-border-subtle)]">
                    {filteredJa4.map((j) => (
                      <tr key={j.fingerprint} className="hover:bg-[var(--color-surface-2)] transition-colors">
                        <td className="py-3 px-4 text-mono font-medium text-[var(--color-accent)]">
                          {j.fingerprint}
                        </td>
                        <td className="py-3 px-4">
                          {j.rarity === 'rare' ? (
                            <span className="badge-critical text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                              RARE / ANOMALOUS
                            </span>
                          ) : j.rarity === 'uncommon' ? (
                            <span className="badge-high text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                              UNCOMMON
                            </span>
                          ) : (
                            <span className="badge-healthy text-[10px] px-2 py-0.5 rounded font-semibold uppercase">
                              COMMON
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-mono font-medium">
                          {j.frequency} sessions
                        </td>
                        <td className="py-3 px-4 text-[12px] text-[var(--color-text-dim)]">
                          {formatDateTime(j.firstSeen)}
                        </td>
                        <td className="py-3 px-4 text-[12px] text-[var(--color-text-dim)]">
                          {formatDateTime(j.lastSeen)}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {j.associatedSessions.map(sid => (
                              <Link
                                key={sid}
                                href={`/sessions/${sid}`}
                                className="px-2 py-0.5 rounded bg-[var(--color-surface-3)] text-mono text-[11px] text-[var(--color-text-secondary)] hover:text-[var(--color-accent)] transition-colors"
                              >
                                {sid}
                              </Link>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

      </div>
    </AppShell>
  );
}
