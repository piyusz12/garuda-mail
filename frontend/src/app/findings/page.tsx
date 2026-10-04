'use client';

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Filter, ChevronRight, Shield, Brain, ShieldAlert, Target, Activity } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { mockFindings } from '@/lib/mock/data';
import Link from 'next/link';
import clsx from 'clsx';
import type { Severity } from '@/types';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] } };
const stagger = { animate: { transition: { staggerChildren: 0.05 } } };

export default function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const severities = ['all', 'critical', 'high', 'medium', 'low', 'informational'];
  const sources = ['all', 'rule_engine', 'ai_anomaly', 'combined'];
  const statuses = ['all', 'open', 'reviewed', 'mitigated', 'accepted', 'false_positive'];

  const sourceLabels: Record<string, string> = {
    all: 'All Sources',
    rule_engine: 'Rule Engine',
    ai_anomaly: 'AI Anomaly',
    combined: 'Combined',
  };

  const filteredFindings = useMemo(() => {
    let findings = [...mockFindings];
    if (severityFilter !== 'all') findings = findings.filter(f => f.severity === severityFilter);
    if (sourceFilter !== 'all') findings = findings.filter(f => f.detectionSource === sourceFilter);
    if (statusFilter !== 'all') findings = findings.filter(f => f.status === statusFilter);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      findings = findings.filter(f =>
        f.title.toLowerCase().includes(q) ||
        f.id.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q) ||
        f.affectedAssets.some(a => a.toLowerCase().includes(q))
      );
    }

    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
    findings.sort((a, b) => order[a.severity] - order[b.severity]);
    return findings;
  }, [severityFilter, sourceFilter, statusFilter, searchQuery]);

  // Aggregates for header
  const openCritical = mockFindings.filter(f => f.severity === 'critical' && f.status === 'open').length;
  const totalAI = mockFindings.filter(f => f.detectionSource === 'ai_anomaly').length;

  return (
    <AppShell title="Security Findings" description="Detected security events requiring investigation">
      <motion.div initial="initial" animate="animate" variants={stagger} className="max-w-[1400px] mx-auto pb-12 space-y-6">

        {/* ── Context Header ── */}
        <motion.div variants={fadeUp} className="card p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-sm rounded-xl relative overflow-hidden">
          <div className="z-10">
            <h1 className="text-[22px] font-bold text-[var(--color-text-primary)] tracking-tight flex items-center gap-2">
              <ShieldAlert size={22} className="text-[var(--color-accent)]" />
              Security Findings
            </h1>
            <p className="text-[13px] text-[var(--color-text-muted)] mt-1 ml-8">Detected security events requiring investigation.</p>
          </div>

          <div className="flex items-center gap-3 z-10 overflow-x-auto hide-scrollbar">
            <div className="flex flex-col p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border-subtle)] min-w-[120px]">
              <span className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold mb-1">Total Findings</span>
              <span className="text-[20px] font-bold text-[var(--color-text-primary)] tabular-nums leading-none">{mockFindings.length}</span>
            </div>
            <div className="flex flex-col p-3 bg-[var(--color-severity-critical-bg)] rounded-lg border border-[var(--color-severity-critical)]/30 min-w-[120px]">
              <span className="text-[10px] uppercase tracking-widest text-[var(--color-severity-critical)] font-bold mb-1">Open Critical</span>
              <span className="text-[20px] font-bold text-[var(--color-severity-critical)] tabular-nums leading-none">{openCritical}</span>
            </div>
            <div className="flex flex-col p-3 bg-[var(--color-accent-dim)] rounded-lg border border-[var(--color-accent)]/30 min-w-[120px]">
              <span className="text-[10px] uppercase tracking-widest text-[var(--color-accent)] font-bold mb-1">AI Detected</span>
              <span className="text-[20px] font-bold text-[var(--color-accent)] tabular-nums leading-none">{totalAI}</span>
            </div>
          </div>

          <div className="absolute -top-32 -right-10 w-64 h-64 bg-[var(--color-accent)] opacity-5 rounded-full blur-3xl pointer-events-none" />
        </motion.div>

        {/* ── Severity Summary Bar ── */}
        <motion.div variants={fadeUp} className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {(['critical', 'high', 'medium', 'low', 'informational'] as Severity[]).map(sev => {
            const count = mockFindings.filter(f => f.severity === sev).length;
            const bgHover: Record<string, string> = {
              critical: 'hover:bg-[var(--color-severity-critical-bg)] hover:border-[var(--color-severity-critical)]/30',
              high: 'hover:bg-[rgba(245,158,11,0.05)] hover:border-[var(--color-severity-high)]/30',
              medium: 'hover:bg-[rgba(234,179,8,0.05)] hover:border-[var(--color-severity-medium)]/30',
              low: 'hover:bg-[rgba(56,189,248,0.05)] hover:border-[var(--color-severity-low)]/30',
              informational: 'hover:bg-[var(--color-surface-3)] hover:border-[var(--color-border)]',
            };
            const textColor: Record<string, string> = {
              critical: 'text-[var(--color-severity-critical)]',
              high: 'text-[var(--color-severity-high)]',
              medium: 'text-[var(--color-severity-medium)]',
              low: 'text-[var(--color-severity-low)]',
              informational: 'text-[var(--color-text-secondary)]',
            };
            const borderColor: Record<string, string> = {
              critical: 'border-[var(--color-severity-critical)]',
              high: 'border-[var(--color-severity-high)]',
              medium: 'border-[var(--color-severity-medium)]',
              low: 'border-[var(--color-severity-low)]',
              informational: 'border-[var(--color-text-secondary)]',
            };
            const isActive = severityFilter === sev;

            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(isActive ? 'all' : sev)}
                className={clsx(
                  'card p-4 text-left transition-all duration-200 border bg-[var(--color-surface-1)] shadow-sm relative overflow-hidden group',
                  bgHover[sev],
                  isActive ? `ring-1 ring-[var(--color-border)] bg-[var(--color-surface-2)]` : 'border-[var(--color-border-subtle)]'
                )}
              >
                <div className={clsx("absolute top-0 bottom-0 left-0 w-1", borderColor[sev])} />
                <div className={clsx('text-2xl font-bold tabular-nums mb-1 ml-2 transition-colors', textColor[sev])}>{count}</div>
                <div className="text-[10px] uppercase tracking-widest text-[var(--color-text-dim)] font-bold ml-2">{sev}</div>
              </button>
            );
          })}
        </motion.div>

        {/* ── Filter / Search Toolbar ── */}
        <motion.div variants={fadeUp} className="flex flex-col md:flex-row items-center gap-4 bg-[var(--color-surface-2)] p-2.5 rounded-xl border border-[var(--color-border-subtle)] shadow-sm">
          <div className="flex items-center gap-3 w-full md:w-auto flex-1 bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-lg px-3 py-2">
            <Filter size={14} className="text-[var(--color-text-dim)]" />
            <input
              type="text"
              placeholder="Filter by ID, Title, Asset, or Category..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-transparent border-none outline-none text-[12px] text-[var(--color-text-primary)] w-full placeholder-[var(--color-text-dim)]"
            />
          </div>

          <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto hide-scrollbar">
            {/* Source Segment */}
            <div className="flex bg-[var(--color-surface-1)] border border-[var(--color-border-subtle)] rounded-lg p-1 shrink-0">
              {sources.map(s => (
                <button
                  key={s}
                  onClick={() => setSourceFilter(s)}
                  className={clsx(
                    'px-3 py-1.5 text-[11px] font-bold rounded-md transition-all',
                    sourceFilter === s
                      ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] shadow-sm'
                      : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
                  )}
                >
                  {sourceLabels[s]}
                </button>
              ))}
            </div>

            {/* Status Segment */}
            <div className="flex bg-[var(--color-surface-1)] border border-[var(--color-border-subtle)] rounded-lg p-1 shrink-0">
              {statuses.map(s => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={clsx(
                    'px-3 py-1.5 text-[11px] font-bold rounded-md transition-all capitalize',
                    statusFilter === s
                      ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] shadow-sm'
                      : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
                  )}
                >
                  {s === 'all' ? 'All' : s.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>

          <div className="text-[11px] font-bold text-[var(--color-text-dim)] whitespace-nowrap px-2">
            {filteredFindings.length} <span className="hidden sm:inline">Results</span>
          </div>
        </motion.div>

        {/* ── Finding Feed ── */}
        <div className="space-y-3">
          {filteredFindings.map((finding, i) => {
            const borderColorMap: Record<string, string> = {
              critical: 'bg-[var(--color-severity-critical)]',
              high: 'bg-[var(--color-severity-high)]',
              medium: 'bg-[var(--color-severity-medium)]',
              low: 'bg-[var(--color-severity-low)]',
              informational: 'bg-[var(--color-text-dim)]',
            };

            return (
              <motion.div
                key={finding.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: Math.min(i * 0.05, 0.5) }} // Cap staggered delay
              >
                <Link href={`/findings/${finding.id}`} className="block relative group bg-[var(--color-surface-1)] rounded-xl border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] hover:bg-[var(--color-surface-2)] transition-all shadow-sm overflow-hidden">

                  {/* Left Severity Accent */}
                  <div className={clsx("absolute top-0 bottom-0 left-0 w-1 transition-opacity opacity-70 group-hover:opacity-100", borderColorMap[finding.severity])} />

                  <div className="p-4 sm:p-5 flex flex-col sm:flex-row gap-4 items-start sm:items-center pl-5 sm:pl-6">

                    {/* Icon / Meta Col */}
                    <div className="flex items-center sm:flex-col sm:items-center gap-3 shrink-0 sm:w-20">
                      <SeverityBadge severity={finding.severity} size="sm" />
                      <div className="flex gap-2">
                        {finding.detectionSource === 'ai_anomaly' ? (
                          <div className="flex items-center justify-center w-6 h-6 rounded bg-[var(--color-accent-dim)] border border-[var(--color-accent)]/20 text-[var(--color-accent)]" title="AI Anomaly">
                            <Brain size={12} />
                          </div>
                        ) : (
                          <div className="flex items-center justify-center w-6 h-6 rounded bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] text-[var(--color-text-secondary)]" title="Rule Engine">
                            <Shield size={12} />
                          </div>
                        )}
                        {finding.status === 'open' && (
                          <div className="flex items-center justify-center w-6 h-6 rounded bg-[var(--color-severity-critical-bg)] border border-[var(--color-severity-critical)]/20 text-[var(--color-severity-critical)] font-bold text-[10px]" title="Open Incident">
                            !
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Main Content */}
                    <div className="flex-1 min-w-0 flex flex-col justify-center">
                      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                        <span className="text-[11px] text-mono font-bold text-[var(--color-text-primary)] px-2 py-0.5 bg-[var(--color-surface-3)] rounded border border-[var(--color-border-subtle)]">{finding.id}</span>
                        <span className="text-[10px] uppercase tracking-widest font-bold text-[var(--color-text-dim)] px-2 py-0.5 rounded border border-[var(--color-border-subtle)]">{finding.category}</span>
                        {finding.status !== 'open' && (
                           <span className="text-[10px] uppercase tracking-widest font-bold text-[var(--color-text-secondary)] px-2 py-0.5 rounded bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)]">{finding.status.replace('_', ' ')}</span>
                        )}
                      </div>

                      <h3 className="text-[15px] font-bold text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] transition-colors mb-1 truncate">
                        {finding.title}
                      </h3>

                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] font-medium text-[var(--color-text-muted)] mt-1">
                        <div className="flex items-center gap-1.5">
                          <Target size={12} className="text-[var(--color-text-dim)]" />
                          <span className="text-mono truncate max-w-[200px]">{finding.affectedAssets.join(', ')}</span>
                        </div>
                        <span className="hidden sm:inline text-[var(--color-border)]">•</span>
                        <div className="flex items-center gap-1.5">
                          <Activity size={12} className="text-[var(--color-text-dim)]" />
                          <span>Confidence: {finding.confidence}%</span>
                        </div>
                        <span className="hidden sm:inline text-[var(--color-border)]">•</span>
                        <span>{finding.evidence.length} Evidence Items</span>
                      </div>
                    </div>

                    {/* Right Nav Indicator */}
                    <div className="hidden sm:flex shrink-0 w-8 h-8 items-center justify-center rounded-full bg-[var(--color-surface-2)] border border-transparent group-hover:border-[var(--color-border)] group-hover:bg-[var(--color-surface-3)] transition-all">
                      <ChevronRight size={14} className="text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors" />
                    </div>
                  </div>
                </Link>
              </motion.div>
            );
          })}

          {filteredFindings.length === 0 && (
            <div className="p-12 card border border-dashed border-[var(--color-border)] flex flex-col items-center justify-center text-center">
              <ShieldAlert size={32} className="text-[var(--color-text-dim)] mb-4" />
              <h3 className="text-[14px] font-bold text-[var(--color-text-primary)] mb-1">No findings match criteria</h3>
              <p className="text-[12px] text-[var(--color-text-muted)]">Try adjusting your filters or search query.</p>
            </div>
          )}
        </div>

      </motion.div>
    </AppShell>
  );
}
