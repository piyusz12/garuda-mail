'use client';

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Filter, ChevronRight, Shield, Brain } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { mockFindings } from '@/lib/mock/data';
import Link from 'next/link';
import clsx from 'clsx';
import type { Severity, DetectionSource } from '@/types';

export default function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

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

    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
    findings.sort((a, b) => order[a.severity] - order[b.severity]);
    return findings;
  }, [severityFilter, sourceFilter, statusFilter]);

  return (
    <AppShell title="Findings" description={`${mockFindings.length} security findings across all analyses`}>
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
        {/* Summary cards */}
        <div className="grid grid-cols-5 gap-3">
          {(['critical', 'high', 'medium', 'low', 'informational'] as Severity[]).map(sev => {
            const count = mockFindings.filter(f => f.severity === sev).length;
            const colorMap: Record<string, string> = {
              critical: 'border-l-[var(--color-severity-critical)]',
              high: 'border-l-[var(--color-severity-high)]',
              medium: 'border-l-[var(--color-severity-medium)]',
              low: 'border-l-[var(--color-severity-low)]',
              informational: 'border-l-[var(--color-severity-info)]',
            };
            const textColor: Record<string, string> = {
              critical: 'text-[var(--color-severity-critical)]',
              high: 'text-[var(--color-severity-high)]',
              medium: 'text-[var(--color-severity-medium)]',
              low: 'text-[var(--color-severity-low)]',
              informational: 'text-[var(--color-severity-info)]',
            };
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? 'all' : sev)}
                className={clsx(
                  'card p-3 border-l-2 text-left transition-all',
                  colorMap[sev],
                  severityFilter === sev ? 'ring-1 ring-[var(--color-accent)]' : 'card-hover'
                )}
              >
                <div className={clsx('text-xl font-bold tabular-nums', textColor[sev])}>{count}</div>
                <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-dim)] capitalize">{sev}</div>
              </button>
            );
          })}
        </div>

        {/* Filters */}
        <div className="card p-3 flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-[var(--color-text-muted)]" />
          </div>
          <div className="flex gap-1">
            {sources.map(s => (
              <button
                key={s}
                onClick={() => setSourceFilter(s)}
                className={clsx(
                  'px-3 py-1.5 text-[11px] font-medium rounded-md transition-colors',
                  sourceFilter === s
                    ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[rgba(56,189,248,0.15)]'
                    : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent'
                )}
              >
                {sourceLabels[s]}
              </button>
            ))}
          </div>
          <div className="w-px h-5 bg-[var(--color-border)]" />
          <div className="flex gap-1">
            {statuses.map(s => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={clsx(
                  'px-3 py-1.5 text-[11px] font-medium rounded-md transition-colors capitalize',
                  statusFilter === s
                    ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] border border-[rgba(56,189,248,0.15)]'
                    : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-2)] border border-transparent'
                )}
              >
                {s === 'all' ? 'All Status' : s.replace('_', ' ')}
              </button>
            ))}
          </div>
          <div className="ml-auto text-[11px] text-[var(--color-text-dim)]">
            {filteredFindings.length} findings
          </div>
        </div>

        {/* Finding Cards */}
        <div className="space-y-3">
          {filteredFindings.map((finding, i) => (
            <motion.div
              key={finding.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
            >
              <Link href={`/findings/${finding.id}`} className="block card card-hover p-4 group">
                <div className="flex items-start gap-4">
                  {/* Left indicator */}
                  <div className="flex flex-col items-center gap-2 pt-0.5">
                    <SeverityBadge severity={finding.severity} size="sm" />
                    {finding.detectionSource === 'ai_anomaly' ? (
                      <span title="AI Detection">
                        <Brain size={14} className="text-[var(--color-accent)]" />
                      </span>
                    ) : (
                      <span title="Rule Engine">
                        <Shield size={14} className="text-[var(--color-text-muted)]" />
                      </span>
                    )}
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[11px] text-mono text-[var(--color-text-dim)]">{finding.id}</span>
                      {finding.ruleId && (
                        <span className="text-[10px] text-mono text-[var(--color-text-dim)] bg-[var(--color-surface-3)] px-1.5 py-0.5 rounded">
                          {finding.ruleId}
                        </span>
                      )}
                    </div>
                    <h3 className="text-[14px] font-semibold text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] transition-colors mb-1">
                      {finding.title}
                    </h3>
                    <p className="text-[12px] text-[var(--color-text-muted)] line-clamp-2 mb-2">
                      {finding.description}
                    </p>
                    <div className="flex items-center gap-4 text-[11px] text-[var(--color-text-dim)]">
                      <span>{finding.category}</span>
                      <span>•</span>
                      <span className="text-mono">{finding.affectedAssets.join(', ')}</span>
                      <span>•</span>
                      <span>Confidence: {finding.confidence}%</span>
                      <span>•</span>
                      <span>{finding.evidence.length} evidence item{finding.evidence.length !== 1 ? 's' : ''}</span>
                    </div>
                  </div>

                  {/* Right arrow */}
                  <ChevronRight size={16} className="text-[var(--color-text-dim)] group-hover:text-[var(--color-accent)] transition-colors mt-1" />
                </div>
              </Link>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </AppShell>
  );
}
