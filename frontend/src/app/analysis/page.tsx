'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload, FileText, Play, CheckCircle2, ArrowRight, Shield, Brain, Layers,
  RefreshCw, Sliders, Cpu, Database, Sparkles, Terminal, Activity, FileSearch, Check
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, StatusBadge, RiskScore } from '@/components/ui/shared';
import { mockAnalyses } from '@/lib/mock/data';
import { formatBytes, formatDateTime } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';

const PIPELINE_STAGES = [
  { id: 'validating', label: 'PCAP Validation', desc: 'Checking magic bytes, headers & timestamps' },
  { id: 'reconstructing', label: 'Session Reconstruction', desc: 'Reassembling TCP streams & tracking state' },
  { id: 'identifying', label: 'Protocol Identification', desc: 'Classifying SMTP, IMAP, POP3 and STARTTLS' },
  { id: 'analyzing_tls', label: 'TLS Cryptographic Audit', desc: 'Parsing Client/Server Hello & cipher suites' },
  { id: 'analyzing_certs', label: 'Certificate Chain Validation', desc: 'Evaluating X.509 chains & trust roots' },
  { id: 'running_rules', label: 'Deterministic Rule Engine', desc: 'Evaluating CVE & weakness policies' },
  { id: 'running_ai', label: 'AI Anomaly Detection', desc: 'Isolation Forest & Autoencoder scoring' },
  { id: 'calculating_risk', label: 'Risk Assessment & Scoring', desc: 'Synthesizing evidence & severity ratings' },
];

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };
const stagger = { animate: { transition: { staggerChildren: 0.05 } } };

export default function AnalysisPage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeStageIndex, setActiveStageIndex] = useState(-1);
  const [progress, setProgress] = useState(0);
  const [completedAnalysis, setCompletedAnalysis] = useState<any | null>(null);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [isDragging, setIsDragging] = useState(false);

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
    }, 800);
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  return (
    <AppShell title="Telemetry Analysis" description="Upload network captures for forensic session and security analysis">
      <motion.div initial="initial" animate="animate" variants={stagger} className="max-w-[1400px] mx-auto pb-12 space-y-6">

        {/* ── Context Header ── */}
        <motion.div variants={fadeUp} className="card p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-sm rounded-xl relative overflow-hidden">
          <div className="z-10">
            <h1 className="text-[22px] font-bold text-[var(--color-text-primary)] tracking-tight flex items-center gap-2">
              <Activity size={22} className="text-[var(--color-accent)]" />
              Telemetry Ingestion
            </h1>
            <p className="text-[13px] text-[var(--color-text-muted)] mt-1 ml-8">Upload network captures for forensic cryptographic session extraction and security analysis.</p>
          </div>
          <div className="absolute -top-32 -right-10 w-64 h-64 bg-[var(--color-accent)] opacity-[0.03] rounded-full blur-3xl pointer-events-none" />
        </motion.div>

        {/* ── Top Upload & Control Grid ── */}
        <motion.div variants={fadeUp} className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Upload Zone (2 cols) */}
          <div className="lg:col-span-2 space-y-4 flex flex-col h-full">
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleFileDrop}
              className={clsx(
                'card p-10 border border-dashed transition-all duration-300 flex flex-col items-center justify-center text-center cursor-pointer flex-1 rounded-xl relative overflow-hidden group',
                isDragging ? 'border-[var(--color-accent)] bg-[var(--color-accent-dim)]' :
                selectedFile ? 'border-[var(--color-accent)] bg-[var(--color-surface-1)]' :
                'border-[var(--color-border)] hover:border-[var(--color-border-hover)] bg-[var(--color-surface-1)] hover:bg-[var(--color-surface-2)]'
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

              {/* Ambient Glow */}
              <div className={clsx("absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-48 h-48 rounded-full blur-3xl pointer-events-none transition-opacity duration-500", (isDragging || selectedFile) ? "opacity-20 bg-[var(--color-accent)]" : "opacity-0")} />

              <div className={clsx("w-16 h-16 rounded-2xl flex items-center justify-center mb-5 border transition-colors shadow-sm z-10",
                 selectedFile ? "bg-[var(--color-surface-2)] border-[var(--color-accent)]/30 text-[var(--color-accent)]" :
                 "bg-[var(--color-surface-3)] border-[var(--color-border)] text-[var(--color-text-muted)] group-hover:text-[var(--color-accent)] group-hover:border-[var(--color-accent)]/30"
              )}>
                <Upload size={28} strokeWidth={2} />
              </div>

              {selectedFile ? (
                <div className="z-10 w-full max-w-sm">
                  <div className="text-[14px] font-bold text-[var(--color-text-primary)] mb-1 flex items-center justify-center gap-2 truncate px-4 py-2 bg-[var(--color-surface-2)] rounded border border-[var(--color-border-subtle)]">
                    <FileText size={16} className="text-[var(--color-accent)] shrink-0" />
                    <span className="truncate">{selectedFile.name}</span>
                  </div>
                  <div className="text-[12px] font-bold text-[var(--color-text-muted)] mt-4 mb-6 uppercase tracking-widest text-mono">
                    {formatBytes(selectedFile.size)} • PCAP Telemetry
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      startAnalysis(selectedFile.name, selectedFile.size);
                    }}
                    disabled={isAnalyzing}
                    className="w-full flex items-center justify-center gap-2 px-6 py-3 text-[13px] font-bold rounded-lg border border-[var(--color-accent)]/30 bg-[var(--color-accent-dim)] text-[var(--color-accent)] hover:bg-[var(--color-accent)] hover:text-[#000] transition-all shadow-sm active:scale-95 disabled:opacity-50 disabled:pointer-events-none"
                  >
                    {isAnalyzing ? (
                      <><RefreshCw size={16} className="animate-spin" /> Ingesting Telemetry...</>
                    ) : (
                      <><Play size={16} /> Execute Analysis Pipeline</>
                    )}
                  </button>
                </div>
              ) : (
                <div className="z-10">
                  <h3 className="text-[15px] font-bold text-[var(--color-text-primary)] mb-2">
                    {isDragging ? 'Drop PCAP to Ingest' : 'Select or drop PCAP/PCAPNG telemetry'}
                  </h3>
                  <p className="text-[13px] text-[var(--color-text-muted)] max-w-md mx-auto mb-6">
                    Supports Wireshark, tcpdump, and tap captures containing SMTP, IMAP, POP3, and TLS handshake traffic.
                  </p>
                  <div className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] text-[12px] font-bold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors shadow-sm">
                    <FileSearch size={16} className="text-[var(--color-text-muted)]" /> Browse Local Files
                  </div>
                </div>
              )}
            </div>

            {/* Quick Demo Sample Action */}
            <div className="card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[var(--color-surface-1)] border-[var(--color-border-subtle)] rounded-xl shrink-0">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-lg bg-[var(--color-accent-dim)] border border-[var(--color-accent)]/20 flex items-center justify-center text-[var(--color-accent)] shrink-0">
                  <Sparkles size={18} />
                </div>
                <div>
                  <div className="text-[13px] font-bold text-[var(--color-text-primary)]">
                    Load Demonstration Telemetry
                  </div>
                  <div className="text-[11px] text-[var(--color-text-muted)] font-medium mt-0.5">
                    Test the pipeline with: <span className="text-mono font-bold text-[var(--color-text-secondary)]">enterprise_mail_q3.pcap</span> (128 MB)
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => startAnalysis('enterprise_mail_q3.pcap', 134217728)}
                disabled={isAnalyzing}
                className="w-full sm:w-auto px-4 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] text-[12px] font-bold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <Play size={14} className="text-[var(--color-accent)]" /> Load Sample
              </button>
            </div>
          </div>

          {/* Analysis Settings (1 col) */}
          <div className="card p-6 flex flex-col h-full bg-[var(--color-surface-1)] border-[var(--color-border)] rounded-xl">
            <div className="flex items-center gap-2 pb-4 border-b border-[var(--color-border-subtle)] mb-5">
              <Sliders size={16} className="text-[var(--color-accent)]" />
              <h3 className="text-[11px] font-bold text-[var(--color-text-primary)] uppercase tracking-widest">
                Inspection Parameters
              </h3>
            </div>

            <div className="space-y-4 flex-1">
              <ParameterToggle
                icon={Brain}
                title="AI Anomaly Detection"
                desc="Behavioral scoring against traffic baseline"
                checked={enableAi}
                onChange={setEnableAi}
              />
              <ParameterToggle
                icon={Shield}
                title="Deep TLS Handshake Audit"
                desc="Inspect cipher suites & JA4 fingerprints"
                checked={deepTls}
                onChange={setDeepTls}
              />
              <ParameterToggle
                icon={Database}
                title="MTA-STS & DANE Verification"
                desc="Cross-check DNS TLSA records & policy"
                checked={checkMtaSts}
                onChange={setCheckMtaSts}
              />
              <ParameterToggle
                icon={Layers}
                title="Retain Raw Packet Traces"
                desc="Store packet evidence for forensic records"
                checked={rawPackets}
                onChange={setRawPackets}
              />
            </div>

            <div className="pt-4 border-t border-[var(--color-border-subtle)] mt-5 flex items-center justify-center gap-2">
               <Cpu size={14} className="text-[var(--color-text-dim)]" />
               <span className="text-[10px] text-[var(--color-text-muted)] font-mono uppercase tracking-widest font-bold text-center">Multi-threaded Rust Engine</span>
            </div>
          </div>
        </motion.div>

        {/* ── Active Pipeline Stage Visualizer ── */}
        {(isAnalyzing || completedAnalysis) && (
          <motion.div
            initial={{ opacity: 0, scale: 0.98, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            transition={{ duration: 0.4, ease: "easeOut" }}
            className="card border border-[var(--color-accent)]/20 bg-[var(--color-surface-1)] shadow-lg rounded-xl overflow-hidden relative"
          >
            {/* Top processing bar */}
            <div className="h-1 w-full bg-[var(--color-surface-3)] relative overflow-hidden">
               <motion.div
                 className={clsx("absolute top-0 bottom-0 left-0", isAnalyzing ? "bg-[var(--color-accent)]" : "bg-[var(--color-severity-healthy)]")}
                 initial={{ width: 0 }}
                 animate={{ width: `${progress}%` }}
                 transition={{ duration: 0.3 }}
               />
            </div>

            <div className="p-6">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-5 mb-8">
                <div>
                  <div className="flex items-center gap-3">
                    <h3 className="text-[18px] font-bold text-[var(--color-text-primary)]">
                      Orchestrating Pipeline
                    </h3>
                    {isAnalyzing ? (
                      <span className="text-[10px] uppercase font-bold tracking-widest px-2 py-0.5 rounded border border-[var(--color-accent)]/30 bg-[var(--color-accent-dim)] text-[var(--color-accent)] flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-accent)] animate-pulse" />
                        Processing ({progress}%)
                      </span>
                    ) : (
                      <span className="text-[10px] uppercase font-bold tracking-widest px-2 py-0.5 rounded border border-[var(--color-severity-healthy)]/30 bg-[var(--color-severity-healthy)]/10 text-[var(--color-severity-healthy)] flex items-center gap-1.5">
                        <Check size={12} />
                        Completed
                      </span>
                    )}
                  </div>
                  <p className="text-[12px] font-medium text-[var(--color-text-muted)] mt-1">
                    Real-time PCAP extraction and cryptographic session synthesis.
                  </p>
                </div>

                {completedAnalysis && (
                  <div className="flex items-center gap-3 w-full sm:w-auto">
                    <Link
                      href="/dashboard"
                      className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-[var(--color-accent)]/30 bg-[var(--color-accent-dim)] text-[var(--color-accent)] text-[12px] font-bold hover:bg-[var(--color-accent)] hover:text-[#000] transition-colors"
                    >
                      Security Posture <ArrowRight size={14} />
                    </Link>
                    <Link
                      href="/sessions"
                      className="flex-1 sm:flex-none flex items-center justify-center px-4 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] text-[12px] font-bold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-3)] transition-colors"
                    >
                      Network Sessions
                    </Link>
                  </div>
                )}
              </div>

              {/* 8-Stage Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 mb-8">
                {PIPELINE_STAGES.map((st, idx) => {
                  const isPast = idx < activeStageIndex;
                  const isCurrent = idx === activeStageIndex;
                  const isFuture = idx > activeStageIndex;

                  return (
                    <div
                      key={st.id}
                      className={clsx(
                        'p-4 rounded-lg border flex items-center gap-3 transition-colors',
                        isPast ? 'bg-[var(--color-severity-healthy)]/5 border-[var(--color-severity-healthy)]/20' :
                        isCurrent ? 'bg-[var(--color-accent-dim)] border-[var(--color-accent)]/40 shadow-[0_0_15px_rgba(56,189,248,0.1)]' :
                        'bg-[var(--color-surface-2)] border-[var(--color-border-subtle)] opacity-50'
                      )}
                    >
                      <div className="flex-shrink-0">
                        {isPast ? (
                          <div className="w-6 h-6 rounded flex items-center justify-center bg-[var(--color-severity-healthy)]/20 text-[var(--color-severity-healthy)]">
                            <Check size={14} strokeWidth={3} />
                          </div>
                        ) : isCurrent ? (
                          <div className="w-6 h-6 rounded flex items-center justify-center bg-[var(--color-accent)]/20 text-[var(--color-accent)]">
                            <RefreshCw size={14} className="animate-spin" />
                          </div>
                        ) : (
                          <div className="w-6 h-6 rounded flex items-center justify-center border border-[var(--color-text-dim)]/50 text-[10px] font-mono font-bold text-[var(--color-text-dim)]">
                            {idx + 1}
                          </div>
                        )}
                      </div>
                      <div className="min-w-0">
                        <div className={clsx(
                          'text-[12px] font-bold truncate',
                          isPast ? 'text-[var(--color-severity-healthy)]' : isCurrent ? 'text-[var(--color-accent)]' : 'text-[var(--color-text-muted)]'
                        )}>
                          {st.label}
                        </div>
                        <div className="text-[10px] text-[var(--color-text-dim)] font-medium leading-tight mt-0.5 truncate">
                          {st.desc}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Pseudo-Terminal Output */}
              <div className="bg-[#05080f] rounded-lg border border-[var(--color-border)] overflow-hidden shadow-inner flex flex-col">
                <div className="flex items-center justify-between px-4 py-2 border-b border-[var(--color-border-subtle)] bg-[#080a10]">
                  <div className="flex items-center gap-2 text-[10px] uppercase tracking-widest font-bold text-[var(--color-text-dim)]">
                    <Terminal size={12} /> Execution Log
                  </div>
                  <div className="flex items-center gap-1.5 text-[9px] font-mono font-bold">
                    <span className={clsx("w-1.5 h-1.5 rounded-full", isAnalyzing ? "bg-[var(--color-accent)] animate-pulse" : "bg-[var(--color-severity-healthy)]")} />
                    <span className={isAnalyzing ? "text-[var(--color-accent)]" : "text-[var(--color-severity-healthy)]"}>{isAnalyzing ? 'ACTIVE' : 'COMPLETE'}</span>
                  </div>
                </div>
                <div className="p-4 font-mono text-[11px] sm:text-[12px] leading-relaxed space-y-1.5 h-64 overflow-y-auto custom-scrollbar flex flex-col-reverse">
                  <div className="flex flex-col gap-1.5">
                    {consoleLogs.map((log, i) => (
                      <div
                        key={i}
                        className={clsx(
                          'pl-3 border-l-2',
                          log.includes('ALERT') ? 'border-[var(--color-severity-critical)] text-[var(--color-severity-critical)] font-semibold' :
                          log.includes('Triggered') ? 'border-[var(--color-severity-high)] text-[var(--color-severity-high)] font-semibold' :
                          log.includes('complete') || log.includes('Identified') ? 'border-[var(--color-severity-healthy)] text-[var(--color-severity-healthy)]' :
                          log.includes('Model inference') || log.includes('Computing') ? 'border-[var(--color-accent)] text-[var(--color-accent)]' :
                          'border-[var(--color-border-subtle)] text-[var(--color-text-secondary)]'
                        )}
                      >
                        {log}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Historical Ingestions Table ── */}
        <motion.div variants={fadeUp} className="card p-6 bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-xl shadow-sm">
          <div className="flex items-center gap-3 mb-6 pb-4 border-b border-[var(--color-border-subtle)]">
            <div className="w-8 h-8 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] flex items-center justify-center">
              <Database size={14} className="text-[var(--color-text-secondary)]" />
            </div>
            <div>
              <h3 className="text-[14px] font-bold text-[var(--color-text-primary)]">
                Telemetry Vault
              </h3>
              <p className="text-[11px] text-[var(--color-text-muted)] font-medium mt-0.5">
                Previously ingested cryptographic captures
              </p>
            </div>
          </div>

          <div className="overflow-x-auto hide-scrollbar">
            <table className="w-full text-left min-w-[900px]">
              <thead>
                <tr className="border-b border-[var(--color-border-subtle)] text-[10px] font-bold text-[var(--color-text-dim)] uppercase tracking-widest bg-[var(--color-surface-2)]">
                  <th className="py-3.5 px-4">Job ID</th>
                  <th className="py-3.5 px-4">Capture File</th>
                  <th className="py-3.5 px-4">Size</th>
                  <th className="py-3.5 px-4">Sessions</th>
                  <th className="py-3.5 px-4">Findings</th>
                  <th className="py-3.5 px-4 text-center">Risk Index</th>
                  <th className="py-3.5 px-4">Status</th>
                  <th className="py-3.5 px-4">Ingested At</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-subtle)]">
                {mockAnalyses.map((job) => (
                  <tr key={job.id} className="hover:bg-[var(--color-surface-2)] transition-colors group">
                    <td className="py-3 px-4 text-[12px] text-mono font-bold text-[var(--color-accent)]">
                      {job.id}
                    </td>
                    <td className="py-3 px-4 font-bold text-[13px] text-[var(--color-text-primary)]">
                      <div className="flex items-center gap-2">
                        <FileText size={14} className="text-[var(--color-text-muted)]" />
                        {job.filename}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-[11px] text-[var(--color-text-secondary)] text-mono font-medium">
                      {formatBytes(job.fileSize)}
                    </td>
                    <td className="py-3 px-4 text-[12px] text-[var(--color-text-secondary)] text-mono font-bold">
                      {job.sessionsCount}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] font-bold text-mono px-1.5 py-0.5 rounded bg-[var(--color-severity-critical-bg)] text-[var(--color-severity-critical)] border border-[var(--color-severity-critical)]/30">
                          {job.criticalCount} C
                        </span>
                        <span className="text-[10px] font-bold text-mono px-1.5 py-0.5 rounded bg-[rgba(245,158,11,0.1)] text-[var(--color-severity-high)] border border-[var(--color-severity-high)]/30">
                          {job.highCount} H
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <RiskScore score={job.overallRisk} size="sm" />
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={job.status} />
                    </td>
                    <td className="py-3 px-4 text-[11px] text-[var(--color-text-dim)] font-mono">
                      {formatDateTime(job.startedAt)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        href="/dashboard"
                        className="inline-flex items-center justify-center text-[11px] font-bold py-1.5 px-3 rounded bg-[var(--color-surface-3)] border border-[var(--color-border-subtle)] text-[var(--color-text-primary)] hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] transition-colors"
                      >
                        Inspect Result
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

      </motion.div>
    </AppShell>
  );
}

function ParameterToggle({ icon: Icon, title, desc, checked, onChange }: any) {
  return (
    <label className="flex items-start gap-4 p-3 rounded-lg border border-[var(--color-border-subtle)] bg-[var(--color-surface-2)] cursor-pointer select-none hover:border-[var(--color-border)] transition-colors group">
      <div className="flex items-center justify-center w-8 h-8 rounded bg-[var(--color-surface-1)] border border-[var(--color-border)] shrink-0 group-hover:border-[var(--color-accent)]/30 transition-colors">
         <Icon size={14} className={clsx("transition-colors", checked ? "text-[var(--color-accent)]" : "text-[var(--color-text-dim)] group-hover:text-[var(--color-text-secondary)]")} />
      </div>
      <div className="flex-1">
        <div className="text-[12px] font-bold text-[var(--color-text-primary)] leading-none mb-1 group-hover:text-[var(--color-accent)] transition-colors">
          {title}
        </div>
        <div className="text-[11px] text-[var(--color-text-dim)] font-medium leading-tight">
          {desc}
        </div>
      </div>
      <div className="shrink-0 pt-1">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          className="rounded bg-[var(--color-surface-3)] border-[var(--color-border)] text-[var(--color-accent)] focus:ring-0 focus:ring-offset-0 w-4 h-4 cursor-pointer"
        />
      </div>
    </label>
  );
}
