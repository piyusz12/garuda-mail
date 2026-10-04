'use client';

import { useState } from 'react';
import { usePcapStore, ThreatItem, Ja4Fingerprint } from '@/lib/store/usePcapStore';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, Brain, Filter,
  Fingerprint, Sparkles, Terminal, ArrowUpRight, Search,
  CheckCircle2, AlertOctagon, Info, Shield
} from 'lucide-react';
import clsx from 'clsx';

export default function ThreatAndJa4Dashboard() {
  const {
    securityScore,
    threats,
    ja4Fingerprints,
    activeJa4Filter,
    setActiveJa4Filter,
  } = usePcapStore();

  const [searchTerm, setSearchTerm] = useState('');

  const filteredThreats = threats.filter(t =>
    t.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    t.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.cve && t.cve.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      {/* ── Top Threat & Posture Metrics ── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Posture Score Radial Widget */}
        <div className="card p-5 bg-[var(--color-surface-1)] border border-[var(--color-border)] flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono uppercase text-[var(--color-text-dim)] block mb-1">
              AI Security Posture Score
            </span>
            <div className="flex items-baseline gap-2">
              <span className={clsx('text-4xl font-extrabold tabular-nums', securityScore >= 80 ? 'text-emerald-400' : securityScore >= 60 ? 'text-amber-400' : 'text-rose-400')}>
                {securityScore}
              </span>
              <span className="text-[12px] text-[var(--color-text-dim)]">/ 100</span>
            </div>
            <p className="text-[11px] text-[var(--color-text-muted)] mt-1 font-medium">
              {securityScore >= 80 ? 'Robust Cryptographic Defenses' : 'Moderate Vulnerability Exposure'}
            </p>
          </div>

          <div className="w-16 h-16 rounded-full border-4 border-dashed border-[var(--color-accent)]/40 flex items-center justify-center animate-spin-slow">
            <Brain size={24} className="text-[var(--color-accent)] animate-pulse" />
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="card p-5 bg-[var(--color-surface-1)] border border-[var(--color-border)] space-y-1">
          <span className="text-[10px] font-mono uppercase text-[var(--color-text-dim)] block">Critical Vulnerabilities</span>
          <div className="text-3xl font-extrabold text-rose-400 tabular-nums">
            {threats.filter(t => t.severity === 'CRITICAL').length}
          </div>
          <p className="text-[11px] text-rose-400/80">BEAST & Weak Key lengths detected</p>
        </div>

        {/* High / Medium Threats */}
        <div className="card p-5 bg-[var(--color-surface-1)] border border-[var(--color-border)] space-y-1">
          <span className="text-[10px] font-mono uppercase text-[var(--color-text-dim)] block">High / Warning Threats</span>
          <div className="text-3xl font-extrabold text-amber-400 tabular-nums">
            {threats.filter(t => t.severity === 'HIGH').length}
          </div>
          <p className="text-[11px] text-amber-400/80">Certificate Expiration & JA4 Beacons</p>
        </div>

        {/* JA4 Fingerprint Diversity */}
        <div className="card p-5 bg-[var(--color-surface-1)] border border-[var(--color-border)] space-y-1">
          <span className="text-[10px] font-mono uppercase text-[var(--color-text-dim)] block">JA4+ Fingerprint Profiles</span>
          <div className="text-3xl font-extrabold text-[var(--color-accent)] tabular-nums">
            {ja4Fingerprints.length}
          </div>
          <p className="text-[11px] text-[var(--color-text-dim)]">1 Malicious, 1 Suspicious script</p>
        </div>
      </div>

      {/* ── JA4+ Fingerprint Explorer ── */}
      <div className="card p-5 bg-[var(--color-surface-1)] border border-[var(--color-border)] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--color-border)]">
          <div>
            <div className="flex items-center gap-2">
              <Fingerprint size={18} className="text-[var(--color-accent)]" />
              <h3 className="text-[15px] font-bold text-[var(--color-text-primary)]">
                JA4+ Network Fingerprint Threat Hunter
              </h3>
            </div>
            <p className="text-[12px] text-[var(--color-text-muted)] mt-0.5">
              Transforming raw TLS ClientHello extensions into standardized 36-character behavioral fingerprints to identify malware C2 & unauthorized bots.
            </p>
          </div>

          {activeJa4Filter && (
            <button
              onClick={() => setActiveJa4Filter(null)}
              className="text-[11px] px-2.5 py-1 rounded bg-[var(--color-surface-3)] text-[var(--color-accent)] border border-[var(--color-border)] hover:bg-[var(--color-surface-2)]"
            >
              Clear Filter: {activeJa4Filter.slice(0, 15)}... ✕
            </button>
          )}
        </div>

        {/* JA4 Fingerprints Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px] border-collapse">
            <thead>
              <tr className="border-b border-[var(--color-border-subtle)] text-[11px] font-mono uppercase text-[var(--color-text-dim)]">
                <th className="py-2.5 px-3">JA4+ Fingerprint Hash</th>
                <th className="py-2.5 px-3">Protocol / Version</th>
                <th className="py-2.5 px-3">Inferred Client Signature</th>
                <th className="py-2.5 px-3">Risk Rating</th>
                <th className="py-2.5 px-3 text-right">Observations</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-border-subtle)] font-mono">
              {ja4Fingerprints.map((ja4, idx) => {
                const isSelected = activeJa4Filter === ja4.hash;
                return (
                  <tr
                    key={idx}
                    onClick={() => setActiveJa4Filter(isSelected ? null : ja4.hash)}
                    className={clsx(
                      'transition-colors cursor-pointer',
                      isSelected
                        ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)]'
                        : 'hover:bg-[var(--color-surface-2)] text-[var(--color-text-secondary)]'
                    )}
                  >
                    <td className="py-3 px-3 font-bold flex items-center gap-2">
                      <span className={clsx('w-2 h-2 rounded-full', ja4.riskRating === 'BENIGN' ? 'bg-emerald-400' : ja4.riskRating === 'SUSPICIOUS' ? 'bg-amber-400' : 'bg-rose-400')} />
                      <span className="font-mono text-[11px] text-[var(--color-text-primary)]">{ja4.hash}</span>
                    </td>
                    <td className="py-3 px-3 text-[11px] text-[var(--color-text-dim)]">
                      {ja4.protocol}
                    </td>
                    <td className="py-3 px-3 text-[11px]">
                      <div>{ja4.userAgentGuess}</div>
                      {ja4.threatName && (
                        <span className="text-[10px] text-rose-400 font-semibold">{ja4.threatName}</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={clsx(
                          'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                          ja4.riskRating === 'BENIGN'
                            ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                            : ja4.riskRating === 'SUSPICIOUS'
                            ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                            : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                        )}
                      >
                        {ja4.riskRating}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right font-bold text-[var(--color-text-primary)]">
                      {ja4.count} flows
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Prioritized AI Security Threat Feed ── */}
      <div className="card p-5 bg-[var(--color-surface-1)] border border-[var(--color-border)] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--color-border)]">
          <div className="flex items-center gap-2">
            <AlertOctagon size={18} className="text-rose-400" />
            <h3 className="text-[15px] font-bold text-[var(--color-text-primary)]">
              Deterministic Rules & AI Threat Detections
            </h3>
          </div>

          <div className="relative w-full sm:w-64">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-dim)]" />
            <input
              type="text"
              placeholder="Search CVE or alert title..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded-md text-[11px] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-dim)] outline-none"
            />
          </div>
        </div>

        <div className="space-y-3">
          {filteredThreats.map(threat => (
            <div
              key={threat.id}
              className={clsx(
                'p-4 rounded-xl border transition-all space-y-2',
                threat.severity === 'CRITICAL'
                  ? 'bg-rose-950/15 border-rose-800/40 hover:border-rose-600/60'
                  : 'bg-amber-950/15 border-amber-800/40 hover:border-amber-600/60'
              )}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span
                    className={clsx(
                      'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider',
                      threat.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                    )}
                  >
                    {threat.severity}
                  </span>
                  <span className="text-[13px] font-bold text-[var(--color-text-primary)]">
                    {threat.title}
                  </span>
                </div>

                {threat.cve && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--color-surface-3)] text-rose-300 border border-rose-800/40 self-start sm:self-auto">
                    {threat.cve}
                  </span>
                )}
              </div>

              <p className="text-[12px] text-[var(--color-text-secondary)] leading-relaxed">
                {threat.description}
              </p>

              <div className="pt-2 border-t border-[var(--color-border-subtle)] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px]">
                <div className="text-[var(--color-text-dim)] font-mono">
                  Affected Target: <span className="text-[var(--color-text-primary)]">{threat.affectedSession}</span>
                </div>
                <div className="text-emerald-400 flex items-center gap-1 font-medium">
                  <CheckCircle2 size={12} />
                  <span>Mitigation: {threat.recommendation}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
