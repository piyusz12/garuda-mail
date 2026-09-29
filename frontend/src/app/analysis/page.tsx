'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload, FileText, Play, CheckCircle2, AlertCircle, Clock,
  ArrowRight, Shield, Brain, Layers, RefreshCw, Download,
  Sliders, Cpu, Database, Sparkles, Check, ChevronRight
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, RiskScore, StatusBadge } from '@/components/ui/shared';
import { mockAnalyses } from '@/lib/mock/data';
import { formatBytes, formatDateTime, formatDuration } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';

const PIPELINE_STAGES = [
  { id: 'validating', label: 'PCAP Validation', desc: 'Checking magic bytes, packet headers & timestamps' },
  { id: 'reconstructing', label: 'Session Reconstruction', desc: 'Reassembling TCP streams & flow state tracking' },
  { id: 'identifying', label: 'Protocol Identification', desc: 'Classifying SMTP, IMAP, POP3 and STARTTLS commands' },
  { id: 'analyzing_tls', label: 'TLS Cryptographic Audit', desc: 'Parsing Client/Server Hello, ciphers & extensions' },
  { id: 'analyzing_certs', label: 'Certificate Chain Validation', desc: 'Evaluating X.509 chains, expiration & trust roots' },
  { id: 'running_rules', label: 'Deterministic Rule Engine', desc: 'Evaluating security policies & CVE/weakness checks' },
  { id: 'running_ai', label: 'AI Anomaly Detection', desc: 'Isolation Forest & Autoencoder behavioral scoring' },
  { id: 'calculating_risk', label: 'Risk Assessment & Scoring', desc: 'Synthesizing evidence, confidence & severity ratings' },
];

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function AnalysisPage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeStageIndex, setActiveStageIndex] = useState(-1);
  const [progress, setProgress] = useState(0);
  const [completedAnalysis, setCompletedAnalysis] = useState<any | null>(null);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);

  // Analysis options
  const [enableAi, setEnableAi] = useState(true);
  const [deepTls, setDeepTls] = useState(true);
  const [checkMtaSts, setCheckMtaSts] = useState(true);
  const [rawPackets, setRawPackets] = useState(true);

  const startAnalysis = (filename = 'enterprise_mail_q3.pcap', size = 134217728) => {
    setIsAnalyzing(true);
    setCompletedAnalysis(null);
    setActiveStageIndex(0);
    setProgress(5);
    setConsoleLogs([
      `[00:00.012] Loading capture file: ${filename} (${formatBytes(size)})`,
      `[00:00.089] PCAP format: Wireshark/tcpdump - libpcap (nanosecond timestamps)`,
      `[00:00.150] Link-layer header type: Ethernet (1)`,
    ]);

    let stage = 0;
    const interval = setInterval(() => {
      stage += 1;
      if (stage < PIPELINE_STAGES.length) {
        setActiveStageIndex(stage);
        setProgress(Math.round(((stage + 1) / PIPELINE_STAGES.length) * 100));

        // Add contextual simulated logs
        const stageLogs: Record<number, string[]> = {
          1: [
            `[00:00.410] Reassembling 248 TCP bidirectional flows...`,
            `[00:00.620] Zero TCP checksum errors detected. TCP window scale options preserved.`,
          ],
          2: [
            `[00:01.020] Identified 198 SMTP sessions (Ports 25, 587, 465)`,
            `[00:01.210] Identified 38 IMAP sessions (Ports 143, 993)`,
            `[00:01.340] Identified 12 POP3 sessions (Ports 110, 995)`,
          ],
          3: [
            `[00:01.890] Extracted 215 TLS handshakes. TLS versions: 1.3 (42), 1.2 (168), 1.0 (5)`,
            `[00:02.100] Found deprecated cipher: TLS_RSA_WITH_AES_128_CBC_SHA in session SMTP-0193`,
            `[00:02.240] Parsed 248 JA4 fingerprints (e.g. t13d1516h2_8daaf6152771_e5627efa2ab1)`,
          ],
          4: [
            `[00:02.750] Validated 14 unique X.509 certificate chains`,
            `[00:02.910] ALERT: Certificate for mail.example.com expires in 18 days!`,
            `[00:03.020] ALERT: Expired certificate detected on legacy POP3 gateway (pop3.legacy-mail.internal)`,
          ],
          5: [
            `[00:03.480] Evaluated 42 security rules against extracted telemetry`,
            `[00:03.710] Triggered RULE-TLS-DEPRECATED-001 (Critical - TLS 1.0 in use)`,
            `[00:03.880] Triggered RULE-STARTTLS-MISSING-001 (Critical - Cleartext credentials on IMAP port 143)`,
          ],
          6: [
            `[00:04.220] Passing session feature vectors to AI Anomaly Engine...`,
            `[00:04.450] Model inference complete. 9 behavioral anomalies flagged.`,
            `[00:04.600] Top anomaly: Session SMTP-0192 (Score: 67, Unusual cipher suite order)`,
          ],
          7: [
            `[00:04.910] Computing multi-dimensional forensic risk score...`,
            `[00:05.110] Overall Risk Score: 78/100 (HIGH RISK). Findings: 3 Critical, 7 High, 4 Medium.`,
            `[00:05.280] Cryptographic forensic synthesis complete. Ready for inspection.`,
          ],
        };

        if (stageLogs[stage]) {
          setConsoleLogs(prev => [...prev, ...stageLogs[stage]]);
        }
      } else {
        clearInterval(interval);
        setActiveStageIndex(PIPELINE_STAGES.length);
        setProgress(100);
        setIsAnalyzing(false);
        setCompletedAnalysis(mockAnalyses[0]);
      }
    }, 700);
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  return (
    <AppShell
      title="Analysis & Ingestion"
      description="Upload email network PCAP captures to execute multi-stage cryptographic forensic inspection"
    >
      <div className="space-y-6">

        {/* ── Top Upload & Control Grid ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Upload Zone (2 cols) */}
          <div className="lg:col-span-2 space-y-4">
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleFileDrop}
              className={clsx(
                'card p-8 border-2 border-dashed transition-all duration-200 flex flex-col items-center justify-center text-center cursor-pointer',
                selectedFile
                  ? 'border-[var(--color-accent)] bg-[rgba(56,189,248,0.03)]'
                  : 'border-[var(--color-border)] hover:border-[var(--color-border-hover)] bg-[var(--color-surface-1)]'
              )}
              onClick={() => document.getElementById('pcap-upload-input')?.click()}
            >
              <input
                id="pcap-upload-input"
                type="file"
                accept=".pcap,.pcapng,.cap"
                className="hidden"
                onChange={handleFileInput}
              />

              <div className="w-14 h-14 rounded-2xl bg-[var(--color-surface-2)] border border-[var(--color-border)] flex items-center justify-center mb-4 text-[var(--color-accent)] shadow-sm">
                <Upload size={26} strokeWidth={2} />
              </div>

              {selectedFile ? (
                <div>
                  <div className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1 flex items-center justify-center gap-2">
                    <FileText size={16} className="text-[var(--color-accent)]" />
                    {selectedFile.name}
                  </div>
                  <div className="text-[12px] text-[var(--color-text-muted)] mb-4">
                    {formatBytes(selectedFile.size)} • PCAP Network Capture
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      startAnalysis(selectedFile.name, selectedFile.size);
                    }}
                    disabled={isAnalyzing}
                    className="btn btn-primary px-5 py-2 inline-flex items-center gap-2 text-[13px]"
                  >
                    {isAnalyzing ? (
                      <>
                        <RefreshCw size={15} className="animate-spin" /> Analyzing Capture...
                      </>
                    ) : (
                      <>
                        <Play size={15} /> Execute Analysis Pipeline
                      </>
                    )}
                  </button>
                </div>
              ) : (
                <div>
                  <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">
                    Drop PCAP / PCAPNG capture file here
                  </h3>
                  <p className="text-[12px] text-[var(--color-text-muted)] max-w-sm mb-4">
                    Supports Wireshark, tcpdump, and network tap captures containing SMTP (25, 587, 465), IMAP (143, 993), and POP3 (110, 995) traffic.
                  </p>
                  <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] text-[12px] font-medium text-[var(--color-text-secondary)]">
                    Browse Local File
                  </div>
                </div>
              )}
            </div>

            {/* Quick Demo Sample Action */}
            <div className="card p-4 flex items-center justify-between bg-[var(--color-surface-1)]">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-[rgba(56,189,248,0.08)] border border-[rgba(56,189,248,0.2)] flex items-center justify-center text-[var(--color-accent)]">
                  <Sparkles size={18} />
                </div>
                <div>
                  <div className="text-[13px] font-semibold text-[var(--color-text-primary)]">
                    Want to test without a capture file?
                  </div>
                  <div className="text-[11px] text-[var(--color-text-muted)]">
                    Load pre-packaged capture: <span className="text-mono text-[var(--color-text-secondary)]">enterprise_mail_q3.pcap</span> (128 MB, 248 sessions)
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => startAnalysis('enterprise_mail_q3.pcap', 134217728)}
                disabled={isAnalyzing}
                className="btn btn-secondary text-[12px] py-1.5 px-3 flex items-center gap-1.5"
              >
                <Play size={13} /> Load Sample
              </button>
            </div>
          </div>

          {/* Analysis Settings (1 col) */}
          <div className="card p-5 space-y-4">
            <div className="flex items-center gap-2 pb-3 border-b border-[var(--color-border)]">
              <Sliders size={16} className="text-[var(--color-accent)]" />
              <h3 className="text-[13px] font-semibold text-[var(--color-text-primary)] uppercase tracking-wider">
                Inspection Parameters
              </h3>
            </div>

            <div className="space-y-3">
              <label className="flex items-start gap-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={enableAi}
                  onChange={(e) => setEnableAi(e.target.checked)}
                  className="mt-1 rounded bg-[var(--color-surface-3)] border-[var(--color-border)] text-[var(--color-accent)] focus:ring-0"
                />
                <div>
                  <div className="text-[12px] font-medium text-[var(--color-text-primary)] flex items-center gap-1.5">
                    <Brain size={13} className="text-[var(--color-accent)]" /> AI Anomaly Detection
                  </div>
                  <div className="text-[11px] text-[var(--color-text-dim)]">
                    Behavioral scoring against enterprise traffic baseline
                  </div>
                </div>
              </label>

              <label className="flex items-start gap-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={deepTls}
                  onChange={(e) => setDeepTls(e.target.checked)}
                  className="mt-1 rounded bg-[var(--color-surface-3)] border-[var(--color-border)] text-[var(--color-accent)] focus:ring-0"
                />
                <div>
                  <div className="text-[12px] font-medium text-[var(--color-text-primary)] flex items-center gap-1.5">
                    <Shield size={13} className="text-[var(--color-accent)]" /> Deep TLS Handshake Audit
                  </div>
                  <div className="text-[11px] text-[var(--color-text-dim)]">
                    Inspect cipher suites, extensions & JA4 fingerprints
                  </div>
                </div>
              </label>

              <label className="flex items-start gap-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={checkMtaSts}
                  onChange={(e) => setCheckMtaSts(e.target.checked)}
                  className="mt-1 rounded bg-[var(--color-surface-3)] border-[var(--color-border)] text-[var(--color-accent)] focus:ring-0"
                />
                <div>
                  <div className="text-[12px] font-medium text-[var(--color-text-primary)] flex items-center gap-1.5">
                    <Database size={13} className="text-[var(--color-accent)]" /> MTA-STS & DANE Verification
                  </div>
                  <div className="text-[11px] text-[var(--color-text-dim)]">
                    Cross-check DNS TLSA records and policy compliance
                  </div>
                </div>
              </label>

              <label className="flex items-start gap-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={rawPackets}
                  onChange={(e) => setRawPackets(e.target.checked)}
                  className="mt-1 rounded bg-[var(--color-surface-3)] border-[var(--color-border)] text-[var(--color-accent)] focus:ring-0"
                />
                <div>
                  <div className="text-[12px] font-medium text-[var(--color-text-primary)] flex items-center gap-1.5">
                    <Layers size={13} className="text-[var(--color-accent)]" /> Retain Raw Packet Traces
                  </div>
                  <div className="text-[11px] text-[var(--color-text-dim)]">
                    Store packet evidence for forensic court-ready records
                  </div>
                </div>
              </label>
            </div>

            <div className="pt-3 border-t border-[var(--color-border)] text-[11px] text-[var(--color-text-muted)] flex items-center gap-2">
              <Cpu size={14} className="text-[var(--color-text-dim)] flex-shrink-0" />
              Analysis Engine: Multi-threaded Rust Core + Scapy Reconstructor
            </div>
          </div>
        </div>

        {/* ── Active Pipeline Stage Visualizer ── */}
        {(isAnalyzing || completedAnalysis) && (
          <motion.div
            initial={{ opacity: 0, scale: 0.99 }}
            animate={{ opacity: 1, scale: 1 }}
            className="card p-6 border-[rgba(56,189,248,0.2)] bg-[var(--color-surface-1)] shadow-xl space-y-6"
          >
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2.5">
                  <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
                    Forensic Pipeline Execution
                  </h3>
                  {isAnalyzing ? (
                    <span className="badge-critical text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 animate-pulse">
                      Processing ({progress}%)
                    </span>
                  ) : (
                    <span className="badge-healthy text-[10px] uppercase font-bold tracking-wider px-2 py-0.5">
                      Completed 100%
                    </span>
                  )}
                </div>
                <p className="text-[12px] text-[var(--color-text-muted)] mt-0.5">
                  Real-time pipeline orchestration and telemetry extraction
                </p>
              </div>

              {completedAnalysis && (
                <div className="flex items-center gap-2">
                  <Link
                    href="/dashboard"
                    className="btn btn-primary text-[12px] py-1.5 px-3 flex items-center gap-1.5"
                  >
                    Explore Dashboard <ArrowRight size={14} />
                  </Link>
                  <Link
                    href="/sessions"
                    className="btn btn-secondary text-[12px] py-1.5 px-3 flex items-center gap-1.5"
                  >
                    View Sessions
                  </Link>
                </div>
              )}
            </div>

            {/* Pipeline progress bar */}
            <div className="w-full bg-[var(--color-surface-3)] h-2 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-[var(--color-accent)] to-[var(--color-accent-hover)] transition-all duration-300 rounded-full"
                style={{ width: `${progress}%` }}
              />
            </div>

            {/* 8-Stage Step Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {PIPELINE_STAGES.map((st, idx) => {
                const isPast = idx < activeStageIndex;
                const isCurrent = idx === activeStageIndex;
                return (
                  <div
                    key={st.id}
                    className={clsx(
                      'p-3 rounded-lg border transition-all duration-200 flex items-start gap-2.5',
                      isPast && 'border-[rgba(34,197,94,0.3)] bg-[rgba(34,197,94,0.03)]',
                      isCurrent && 'border-[var(--color-accent)] bg-[rgba(56,189,248,0.06)] ring-1 ring-[var(--color-accent)]',
                      idx > activeStageIndex && 'border-[var(--color-border)] bg-[var(--color-surface-2)] opacity-50'
                    )}
                  >
                    <div className="mt-0.5 flex-shrink-0">
                      {isPast ? (
                        <CheckCircle2 size={16} className="text-[var(--color-severity-healthy)]" />
                      ) : isCurrent ? (
                        <RefreshCw size={16} className="text-[var(--color-accent)] animate-spin" />
                      ) : (
                        <div className="w-4 h-4 rounded-full border border-[var(--color-text-dim)] flex items-center justify-center text-[9px] text-[var(--color-text-dim)]">
                          {idx + 1}
                        </div>
                      )}
                    </div>
                    <div className="min-w-0">
                      <div className={clsx(
                        'text-[12px] font-semibold truncate',
                        isPast ? 'text-[var(--color-text-primary)]' : isCurrent ? 'text-[var(--color-accent)]' : 'text-[var(--color-text-muted)]'
                      )}>
                        {st.label}
                      </div>
                      <div className="text-[10px] text-[var(--color-text-dim)] leading-tight mt-0.5">
                        {st.desc}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Live Terminal Output */}
            <div className="bg-[#05080f] rounded-lg border border-[var(--color-border)] p-4 font-mono text-[11px] space-y-1 max-h-48 overflow-y-auto">
              <div className="text-[var(--color-text-dim)] border-b border-[var(--color-border)] pb-1 mb-2 flex items-center justify-between">
                <span>[PIPELINE_ORCHESTRATOR_LOGS]</span>
                <span className="text-[10px] text-[var(--color-accent)]">STREAM ACTIVE</span>
              </div>
              {consoleLogs.map((log, i) => (
                <div
                  key={i}
                  className={clsx(
                    'leading-relaxed',
                    log.includes('ALERT') ? 'text-[var(--color-severity-critical)] font-semibold' :
                    log.includes('Triggered') ? 'text-[var(--color-severity-high)]' :
                    log.includes('complete') || log.includes('Identified') ? 'text-[var(--color-severity-healthy)]' :
                    'text-[var(--color-text-muted)]'
                  )}
                >
                  {log}
                </div>
              ))}
            </div>
          </motion.div>
        )}

        {/* ── Historical Ingestions / Analysis Jobs Table ── */}
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
                Analysis History
              </h3>
              <p className="text-[12px] text-[var(--color-text-muted)]">
                Previously ingested PCAP network captures and resulting forensic intelligence
              </p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[11px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                  <th className="py-2.5 px-3">Job ID</th>
                  <th className="py-2.5 px-3">Capture File</th>
                  <th className="py-2.5 px-3">File Size</th>
                  <th className="py-2.5 px-3">Sessions</th>
                  <th className="py-2.5 px-3">Findings</th>
                  <th className="py-2.5 px-3">Risk Rating</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Analyzed At</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-subtle)]">
                {mockAnalyses.map((job) => (
                  <tr key={job.id} className="hover:bg-[var(--color-surface-2)] transition-colors">
                    <td className="py-3 px-3 text-mono font-medium text-[var(--color-accent)]">
                      {job.id}
                    </td>
                    <td className="py-3 px-3 font-medium text-[var(--color-text-primary)]">
                      <div className="flex items-center gap-2">
                        <FileText size={15} className="text-[var(--color-text-muted)]" />
                        {job.filename}
                      </div>
                    </td>
                    <td className="py-3 px-3 text-[var(--color-text-secondary)] text-mono">
                      {formatBytes(job.fileSize)}
                    </td>
                    <td className="py-3 px-3 text-mono font-medium">
                      {job.sessionsCount}
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5">
                        <span className="badge-critical text-[10px] px-1.5 py-0.5 rounded font-bold">
                          {job.criticalCount} crit
                        </span>
                        <span className="badge-high text-[10px] px-1.5 py-0.5 rounded font-bold">
                          {job.highCount} high
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <span className={clsx(
                          'text-mono font-bold text-sm',
                          job.overallRisk >= 75 ? 'text-[var(--color-severity-critical)]' :
                          job.overallRisk >= 50 ? 'text-[var(--color-severity-high)]' :
                          'text-[var(--color-severity-medium)]'
                        )}>
                          {job.overallRisk}/100
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <StatusBadge status={job.status} />
                    </td>
                    <td className="py-3 px-3 text-[12px] text-[var(--color-text-dim)]">
                      {formatDateTime(job.startedAt)}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          href="/dashboard"
                          className="btn btn-ghost text-[11px] py-1 px-2 text-[var(--color-accent)] hover:text-white"
                          title="View findings and forensic telemetry"
                        >
                          View Results
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </AppShell>
  );
}
