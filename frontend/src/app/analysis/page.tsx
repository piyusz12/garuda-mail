'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload, FileText, Play, CheckCircle2, AlertCircle, Clock,
  ArrowRight, Shield, Brain, Layers, RefreshCw, Download,
  Sliders, Cpu, Database, Sparkles, Check, ChevronRight,
  Printer, Network, Award, Fingerprint, Lock
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, RiskScore, StatusBadge } from '@/components/ui/shared';
import { mockAnalyses } from '@/lib/mock/data';
import { formatBytes, formatDateTime, formatDuration } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';
import { usePcapStore } from '@/lib/store/usePcapStore';
import TlsSequenceDiagram from '@/components/forensics/TlsSequenceDiagram';
import CertificateTrustGraph from '@/components/forensics/CertificateTrustGraph';
import ThreatAndJa4Dashboard from '@/components/forensics/ThreatAndJa4Dashboard';
import ForensicReportModal from '@/components/forensics/ForensicReportModal';

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

type TabType = 'sequence' | 'certs' | 'threats' | 'ingestion';

export default function AnalysisPage() {
  const {
    fileName,
    fileSizeBytes,
    packetCount,
    isProcessing,
    securityScore,
    loadFile,
    loadSampleSession,
  } = usePcapStore();

  const [activeTab, setActiveTab] = useState<TabType>('sequence');
  const [showReportModal, setShowReportModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [activeStageIndex, setActiveStageIndex] = useState(-1);
  const [progress, setProgress] = useState(0);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([
    `[00:00.012] Ready for local zero-latency packet analysis (100% air-gapped).`,
    `[00:00.089] WASM Deep Packet Inspection Engine initialized.`,
  ]);

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      loadFile(file);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      loadFile(file);
    }
  };

  return (
    <AppShell
      title="Cryptographic Forensic Dashboard"
      description="Zero-latency local PCAP stream reassembly, TLS Sequence Flow (React Flow), X.509 Trust Graph (Cytoscape), and JA4+ Threat Hunter"
    >
      <div className="space-y-6">

        {/* ── Top Command & Export Bar ── */}
        <div className="card p-4 bg-[var(--color-surface-1)] border border-[var(--color-border)] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[var(--color-accent-dim)] border border-[var(--color-accent)]/30 flex items-center justify-center text-[var(--color-accent)]">
              <Shield size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[14px] font-bold text-[var(--color-text-primary)]">
                  {fileName || 'enterprise_mail_demo.pcap'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                  AIR-GAPPED (WASM)
                </span>
                <span className="text-[11px] text-[var(--color-text-dim)] font-mono">
                  {packetCount} Packets Reassembled
                </span>
              </div>
              <p className="text-[11px] text-[var(--color-text-muted)] mt-0.5">
                Local in-browser packet inspection • No packets transmitted outside this PC
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-end md:self-auto">
            <button
              onClick={loadSampleSession}
              className="px-3 py-1.5 rounded-lg text-[12px] font-medium bg-[var(--color-surface-2)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)] transition-colors flex items-center gap-1.5"
            >
              <Sparkles size={13} className="text-[var(--color-accent)]" />
              <span>Load Sample PCAP</span>
            </button>

            <button
              onClick={() => setShowReportModal(true)}
              className="px-4 py-1.5 rounded-lg text-[12px] font-bold bg-[var(--color-accent)] text-[#0B0D10] hover:bg-[#5ccbfc] shadow-md transition-all flex items-center gap-1.5"
            >
              <FileText size={14} />
              <span>Generate Forensic Dossier</span>
            </button>
          </div>
        </div>

        {/* ── Tabbed View Switcher ── */}
        <div className="flex items-center gap-1 p-1 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[12px] font-medium">
          <button
            onClick={() => setActiveTab('sequence')}
            className={clsx(
              'flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg transition-all',
              activeTab === 'sequence'
                ? 'bg-[var(--color-surface-0)] text-[var(--color-text-primary)] font-bold shadow-sm border border-[var(--color-border)]'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
            )}
          >
            <Network size={14} className={activeTab === 'sequence' ? 'text-[var(--color-accent)]' : ''} />
            <span>Phase 3: TLS Sequence Flow (React Flow)</span>
          </button>

          <button
            onClick={() => setActiveTab('certs')}
            className={clsx(
              'flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg transition-all',
              activeTab === 'certs'
                ? 'bg-[var(--color-surface-0)] text-[var(--color-text-primary)] font-bold shadow-sm border border-[var(--color-border)]'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
            )}
          >
            <Award size={14} className={activeTab === 'certs' ? 'text-[var(--color-accent)]' : ''} />
            <span>Phase 4: X.509 Trust Graph (Cytoscape)</span>
          </button>

          <button
            onClick={() => setActiveTab('threats')}
            className={clsx(
              'flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg transition-all',
              activeTab === 'threats'
                ? 'bg-[var(--color-surface-0)] text-[var(--color-text-primary)] font-bold shadow-sm border border-[var(--color-border)]'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
            )}
          >
            <Brain size={14} className={activeTab === 'threats' ? 'text-[var(--color-accent)]' : ''} />
            <span>Phase 5: AI Posture & JA4+ Hunter</span>
          </button>

          <button
            onClick={() => setActiveTab('ingestion')}
            className={clsx(
              'flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg transition-all',
              activeTab === 'ingestion'
                ? 'bg-[var(--color-surface-0)] text-[var(--color-text-primary)] font-bold shadow-sm border border-[var(--color-border)]'
                : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
            )}
          >
            <Upload size={14} className={activeTab === 'ingestion' ? 'text-[var(--color-accent)]' : ''} />
            <span>Phase 2: Local PCAP Ingestion</span>
          </button>
        </div>

        {/* ── Tab Content Views ── */}
        <div>
          {activeTab === 'sequence' && (
            <motion.div {...fadeUp}>
              <TlsSequenceDiagram />
            </motion.div>
          )}

          {activeTab === 'certs' && (
            <motion.div {...fadeUp}>
              <CertificateTrustGraph />
            </motion.div>
          )}

          {activeTab === 'threats' && (
            <motion.div {...fadeUp}>
              <ThreatAndJa4Dashboard />
            </motion.div>
          )}

          {activeTab === 'ingestion' && (
            <motion.div {...fadeUp} className="space-y-6">
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

                <h3 className="text-[15px] font-semibold text-[var(--color-text-primary)] mb-1">
                  Drop PCAP / PCAPNG capture file here for zero-latency local analysis
                </h3>
                <p className="text-[12px] text-[var(--color-text-muted)] max-w-sm mb-4">
                  100% Air-gapped in browser memory. Supports Wireshark, tcpdump, SMTP (25, 587, 465), IMAP (143, 993), and POP3 (110, 995) captures.
                </p>
                <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] text-[12px] font-medium text-[var(--color-text-secondary)]">
                  Browse Local File
                </div>
              </div>

              {/* Wire Reassembly Logs */}
              <div className="card p-4 bg-[#070b14] border border-[var(--color-border)] font-mono text-[11px] space-y-1 text-slate-300">
                <div className="text-[10px] text-slate-500 uppercase tracking-widest pb-2 border-b border-slate-800">
                  WASM Stream Reassembly Wire Logs
                </div>
                {consoleLogs.map((log, i) => (
                  <div key={i} className="text-emerald-400/90 leading-relaxed">
                    {log}
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </div>

        {/* ── Forensic Report Export Modal (Phase 6) ── */}
        <ForensicReportModal
          isOpen={showReportModal}
          onClose={() => setShowReportModal(false)}
        />

      </div>
    </AppShell>
  );
}
