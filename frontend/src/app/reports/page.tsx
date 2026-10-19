'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileText, Download, Eye, Sparkles, Printer, CheckCircle,
  Clock, Shield, AlertTriangle, FileCode, Check, X, RefreshCw
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, RiskScore, StatusBadge } from '@/components/ui/shared';
import { mockReports, mockAnalyses, mockRisk, mockFindings } from '@/lib/mock/data';
import { formatBytes, formatDateTime } from '@/lib/formatters';
import Link from 'next/link';
import clsx from 'clsx';
import type { Report } from '@/types';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>(mockReports);
  const [selectedAnalysis, setSelectedAnalysis] = useState<string>(mockAnalyses[0].id);
  const [reportType, setReportType] = useState<'executive' | 'technical' | 'json' | 'certin'>('executive');
  const [reportFormat, setReportFormat] = useState<'PDF' | 'HTML' | 'JSON'>('PDF');
  const [isGenerating, setIsGenerating] = useState(false);
  const [previewReport, setPreviewReport] = useState<Report | null>(null);

  const handleGenerate = () => {
    setIsGenerating(true);
    setTimeout(() => {
      const newReport: Report = {
        id: `RPT-${reportType === 'executive' ? 'EX' : reportType === 'technical' ? 'TH' : reportType === 'certin' ? 'CERTIN' : 'JS'}-00${reports.length + 1}`,
        type: reportType === 'certin' ? 'technical' : reportType,
        title: reportType === 'executive'
          ? `Executive Cryptographic Forensic Report — ${selectedAnalysis}`
          : reportType === 'technical'
          ? `Technical Forensic Deep Dive Audit — ${selectedAnalysis}`
          : reportType === 'certin'
          ? `CERT-In Directive 70B Incident Evidence Dossier — ${selectedAnalysis}`
          : `Machine-Readable Forensic JSON — ${selectedAnalysis}`,
        analysisId: selectedAnalysis,
        generatedAt: new Date().toISOString(),
        format: reportFormat,
        size: reportType === 'executive' ? 2457600 : reportType === 'technical' ? 8912400 : reportType === 'certin' ? 3145728 : 1245184,
        status: 'ready',
      };
      setReports([newReport, ...reports]);
      setIsGenerating(false);
      setPreviewReport(newReport);
    }, 1200);
  };

  const handleDownload = (rpt: Report) => {
    const dummyContent = JSON.stringify(rpt, null, 2);
    const blob = new Blob([dummyContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${rpt.id}.${rpt.format.toLowerCase()}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AppShell
      title="Forensic & Executive Reports"
      description="Generate court-ready technical audits, executive security summaries, and machine-readable cryptographic dossiers"
    >
      <div className="space-y-6">

        {/* ── Report Generation Studio ── */}
        <div className="card p-6 border-[rgba(56,189,248,0.2)] bg-[var(--color-surface-1)] space-y-5">
          <div className="flex items-center gap-2.5 pb-3 border-b border-[var(--color-border)]">
            <Sparkles size={18} className="text-[var(--color-accent)]" />
            <h3 className="text-base font-bold text-[var(--color-text-primary)]">
              Report Generation Studio
            </h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            
            {/* Target Analysis Run */}
            <div className="space-y-1.5">
              <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                Target Capture Ingestion
              </label>
              <select
                value={selectedAnalysis}
                onChange={(e) => setSelectedAnalysis(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
              >
                {mockAnalyses.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.id} — {a.filename} ({a.sessionsCount} sessions)
                  </option>
                ))}
              </select>
            </div>

            {/* Scope / Report Type */}
            <div className="space-y-1.5">
              <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                Dossier Scope & Audience
              </label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value as any)}
                className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
              >
                <option value="executive">Executive Summary (CISO & Board)</option>
                <option value="technical">Full Forensic Technical Audit (Court/SOC)</option>
                <option value="certin">CERT-In Directive 70B Incident Notice (6-Hour Window)</option>
                <option value="json">Machine-Readable Cryptographic JSON (SIEM)</option>
              </select>
            </div>

            {/* Export Format */}
            <div className="space-y-1.5">
              <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                Document Format
              </label>
              <select
                value={reportFormat}
                onChange={(e) => setReportFormat(e.target.value as any)}
                className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
              >
                <option value="PDF">PDF (Printable Vector)</option>
                <option value="HTML">Standalone HTML Dossier</option>
                <option value="JSON">Structured JSON</option>
              </select>
            </div>

          </div>

          <div className="flex justify-end pt-2">
            <button
              onClick={handleGenerate}
              disabled={isGenerating}
              className="btn btn-primary text-[13px] px-5 py-2 flex items-center gap-2"
            >
              {isGenerating ? (
                <>
                  <RefreshCw size={15} className="animate-spin" /> Compiling Report Dossier...
                </>
              ) : (
                <>
                  <FileText size={15} /> Compile & Generate Report
                </>
              )}
            </button>
          </div>
        </div>

        {/* ── CERT-In Directive 70B Incident Readiness Module ── */}
        <div className="card p-6 border-amber-500/30 bg-gradient-to-br from-[var(--color-surface-1)] to-amber-950/10 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--color-border)]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
                <Shield size={18} />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                    CERT-In Directive 70B Incident Evidence & Readiness
                  </h3>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    DIRECTIONS 28 APR 2022
                  </span>
                </div>
                <p className="text-[12px] text-[var(--color-text-muted)] mt-0.5">
                  Assists Indian enterprise SOCs in assembling verifiable cryptographic proof within the statutory 6-hour incident disclosure window
                </p>
              </div>
            </div>

            <button
              onClick={() => {
                setReportType('certin');
                handleGenerate();
              }}
              disabled={isGenerating}
              className="btn btn-secondary border-amber-500/40 text-amber-300 hover:bg-amber-500/10 text-xs px-3.5 py-1.5 flex items-center gap-1.5 flex-shrink-0 self-start sm:self-auto"
            >
              <FileCode size={14} /> Quick-Export CERT-In Notice
            </button>
          </div>

          {/* Regulatory Scope Clarity Notice */}
          <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-500/20 text-[11px] text-amber-200/90 leading-relaxed flex items-start gap-2.5">
            <AlertTriangle size={15} className="text-amber-400 flex-shrink-0 mt-0.5" />
            <div>
              <b className="text-amber-300">Regulatory Advisory & Forensic Scope:</b> GARUDA assists organizations in preparing forensic evidence, packet artifacts, and audit information relevant to CERT-In incident-response requirements under sub-section (6) of section 70B of the Information Technology Act, 2000. It does not replace internal incident triage procedures or statutory CISO sign-off.
            </div>
          </div>

          {/* 5-Point Statutory Readiness Checklist */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-1">
            <div className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-emerald-500/30 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-slate-200">Incident Evidence</span>
                <CheckCircle size={14} className="text-emerald-400" />
              </div>
              <div className="text-[10px] text-emerald-400 font-semibold font-mono">AVAILABLE ✅</div>
              <p className="text-[10px] text-[var(--color-text-dim)] leading-tight">
                PCAP packet range 1822–1825, ClientHello & ServerHello hex bytes indexed.
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-emerald-500/30 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-slate-200">NTP Clock Sync</span>
                <Clock size={14} className="text-emerald-400" />
              </div>
              <div className="text-[10px] text-emerald-400 font-semibold font-mono">SYNCHRONIZED ✅</div>
              <p className="text-[10px] text-[var(--color-text-dim)] leading-tight">
                IST (UTC+5:30) microsecond timestamps linked to NPL India Stratum-1.
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-emerald-500/30 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-slate-200">Relevant ICT Logs</span>
                <CheckCircle size={14} className="text-emerald-400" />
              </div>
              <div className="text-[10px] text-emerald-400 font-semibold font-mono">180-DAY READY ✅</div>
              <p className="text-[10px] text-[var(--color-text-dim)] leading-tight">
                Passive session flow hashes & cryptographic states archived securely.
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-emerald-500/30 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-slate-200">Forensic Report</span>
                <FileText size={14} className="text-emerald-400" />
              </div>
              <div className="text-[10px] text-emerald-400 font-semibold font-mono">GENERATED ✅</div>
              <p className="text-[10px] text-[var(--color-text-dim)] leading-tight">
                Court-ready cryptographic attestation with RFC standards violation proofs.
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-emerald-500/30 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-slate-200">Notice Exportable</span>
                <Download size={14} className="text-emerald-400" />
              </div>
              <div className="text-[10px] text-emerald-400 font-semibold font-mono">READY TO DISCLOSE ✅</div>
              <p className="text-[10px] text-[var(--color-text-dim)] leading-tight">
                Pre-formatted Annexure-I template for instant dispatch to incident@cert-in.org.in.
              </p>
            </div>
          </div>
        </div>

        {/* ── Generated Reports Archive Table ── */}
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
                Compiled Reports Archive
              </h3>
              <p className="text-[12px] text-[var(--color-text-muted)]">
                Cryptographically signed report dossiers available for download or executive preview
              </p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-2)] text-[11px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                  <th className="py-3 px-4">Report Identifier</th>
                  <th className="py-3 px-4">Dossier Title</th>
                  <th className="py-3 px-4">Analysis Run</th>
                  <th className="py-3 px-4">Format</th>
                  <th className="py-3 px-4">File Size</th>
                  <th className="py-3 px-4">Generated At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-subtle)]">
                {reports.map((rpt) => (
                  <tr key={rpt.id} className="hover:bg-[var(--color-surface-2)] transition-colors">
                    <td className="py-3 px-4 text-mono font-medium text-[var(--color-accent)]">
                      {rpt.id}
                    </td>
                    <td className="py-3 px-4 font-semibold text-[var(--color-text-primary)]">
                      <div className="flex items-center gap-2">
                        <FileText size={15} className="text-[var(--color-text-muted)] flex-shrink-0" />
                        <span>{rpt.title}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-mono text-[var(--color-text-secondary)]">
                      {rpt.analysisId}
                    </td>
                    <td className="py-3 px-4">
                      <span className={clsx(
                        'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                        rpt.format === 'PDF' ? 'bg-[rgba(239,68,68,0.15)] text-[var(--color-severity-critical)]' :
                        rpt.format === 'JSON' ? 'bg-[rgba(56,189,248,0.15)] text-[var(--color-accent)]' :
                        'bg-[rgba(34,197,94,0.15)] text-[var(--color-severity-healthy)]'
                      )}>
                        {rpt.format}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-mono text-[12px] text-[var(--color-text-dim)]">
                      {formatBytes(rpt.size)}
                    </td>
                    <td className="py-3 px-4 text-[12px] text-[var(--color-text-dim)]">
                      {formatDateTime(rpt.generatedAt)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setPreviewReport(rpt)}
                          className="btn btn-ghost text-[11px] py-1 px-2 text-[var(--color-accent)] hover:text-white flex items-center gap-1"
                        >
                          <Eye size={13} /> Preview
                        </button>
                        <button
                          onClick={() => handleDownload(rpt)}
                          className="btn btn-secondary text-[11px] py-1 px-2 flex items-center gap-1"
                        >
                          <Download size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Document Preview Modal ── */}
        <AnimatePresence>
          {previewReport && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
              <motion.div
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.96 }}
                className="card w-full max-w-3xl bg-[var(--color-surface-1)] border border-[var(--color-border)] shadow-2xl rounded-xl overflow-hidden max-h-[90vh] flex flex-col"
              >
                {/* Modal Toolbar */}
                <div className="p-4 border-b border-[var(--color-border)] flex items-center justify-between bg-[var(--color-surface-2)]">
                  <div className="flex items-center gap-2">
                    <FileText size={18} className="text-[var(--color-accent)]" />
                    <span className="font-bold text-sm text-[var(--color-text-primary)]">
                      Document Preview: {previewReport.id}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => window.print()}
                      className="btn btn-secondary text-[11px] py-1 px-2.5 flex items-center gap-1"
                    >
                      <Printer size={13} /> Print
                    </button>
                    <button
                      onClick={() => handleDownload(previewReport)}
                      className="btn btn-primary text-[11px] py-1 px-2.5 flex items-center gap-1"
                    >
                      <Download size={13} /> Download
                    </button>
                    <button
                      onClick={() => setPreviewReport(null)}
                      className="p-1 rounded text-[var(--color-text-muted)] hover:text-white"
                    >
                      <X size={18} />
                    </button>
                  </div>
                </div>

                {/* Printable Document Body */}
                <div className="p-8 overflow-y-auto space-y-6 bg-white text-slate-900 font-sans">
                  {previewReport.id.includes('CERTIN') || previewReport.title.includes('CERT-In') ? (
                    /* CERT-In Annexure-I Cyber Incident Reporting Notice */
                    <div className="space-y-6 text-slate-900">
                      <div className="border-b-2 border-slate-900 pb-4 text-center space-y-1">
                        <div className="text-[12px] font-bold text-slate-600 tracking-wider uppercase">
                          FORM OF REPORTING CYBER INCIDENT TO CERT-IN
                        </div>
                        <div className="text-lg font-black tracking-tight text-slate-950 uppercase">
                          INDIAN COMPUTER EMERGENCY RESPONSE TEAM (CERT-In)
                        </div>
                        <div className="text-[11px] text-slate-500 font-semibold">
                          Directions under sub-section (6) of section 70B of the Information Technology Act, 2000 (Annexure-I)
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-4 p-3 bg-slate-50 rounded border border-slate-200 text-[11px] font-mono">
                        <div><b>INCIDENT DOSSIER REF:</b> {previewReport.id}</div>
                        <div><b>STATUTORY FILING WINDOW:</b> &lt; 6 Hours (MANDATORY)</div>
                        <div><b>INGESTION ARTIFACT:</b> {previewReport.analysisId}</div>
                        <div><b>NTP SYNC ATTESTATION:</b> IST (UTC+5:30) / Stratum-1 Verified</div>
                      </div>

                      <div className="space-y-3 text-[12px]">
                        <h4 className="font-bold text-slate-950 text-xs uppercase border-b border-slate-300 pb-1">
                          1. Incident Summary & Affected Communication Infrastructure
                        </h4>
                        <div className="grid grid-cols-3 gap-2 bg-slate-100 p-2.5 rounded text-[11px]">
                          <div><span className="text-slate-500">Service Affected:</span> <b>Enterprise SMTP / Mail Relay</b></div>
                          <div><span className="text-slate-500">Protocol Port:</span> <b>TCP 587 (Submission)</b></div>
                          <div><span className="text-slate-500">Classification:</span> <b className="text-rose-600">Cryptographic Regression / STRIPTLS</b></div>
                        </div>

                        <h4 className="font-bold text-slate-950 text-xs uppercase border-b border-slate-300 pb-1 pt-2">
                          2. Forensic Evidence & Packet Sequence Verification
                        </h4>
                        <table className="w-full text-left border-collapse text-[11px]">
                          <thead>
                            <tr className="border-b border-slate-300 text-slate-600">
                              <th className="py-1">Artifact</th>
                              <th className="py-1">Cryptographic Evidence</th>
                              <th className="py-1">Standard Violation</th>
                              <th className="py-1">Confidence</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-200 font-mono">
                            <tr>
                              <td className="py-1.5 font-bold">Packets 1822–1825</td>
                              <td className="py-1.5">TLS 1.0 ClientHello (0x0301) / RSA 1024-bit</td>
                              <td className="py-1.5 text-rose-600">RFC 8996 (TLS 1.0/1.1 Deprecation)</td>
                              <td className="py-1.5 text-emerald-600 font-bold">100%</td>
                            </tr>
                            <tr>
                              <td className="py-1.5 font-bold">Packets 1904–1912</td>
                              <td className="py-1.5">STARTTLS 454 Response Downgrade MITM</td>
                              <td className="py-1.5 text-rose-600">RFC 3207 / RFC 8461 (MTA-STS)</td>
                              <td className="py-1.5 text-emerald-600 font-bold">98.4%</td>
                            </tr>
                            <tr>
                              <td className="py-1.5 font-bold">PQC Assessment</td>
                              <td className="py-1.5">No Post-Quantum Hybrid Group (ML-KEM)</td>
                              <td className="py-1.5 text-amber-600">RFC 10024 / NIST FIPS 203</td>
                              <td className="py-1.5 text-sky-600 font-bold">Readiness: LOW</td>
                            </tr>
                          </tbody>
                        </table>

                        <h4 className="font-bold text-slate-950 text-xs uppercase border-b border-slate-300 pb-1 pt-2">
                          3. Mandatory Section 70B Log Retention & Integrity Signature
                        </h4>
                        <div className="p-3 bg-slate-50 border border-slate-200 rounded text-[11px] space-y-1">
                          <div><b>ICT Retention Guarantee:</b> 180-Day tamper-evident rolling audit log preserved in secure local forensic storage.</div>
                          <div><b>PCAP Integrity Digest:</b> <span className="font-mono text-[10px]">SHA-256: 4f89d0b64e528b12...ec78</span></div>
                          <div><b>Submission Target:</b> Designated CERT-In Reporting Desk (<span className="text-blue-600 underline">incident@cert-in.org.in</span>)</div>
                        </div>
                      </div>

                      {/* Attestation & Signature block */}
                      <div className="pt-4 border-t border-slate-300 flex items-end justify-between text-[11px] text-slate-600">
                        <div>
                          <div>Assembled By: <span className="font-semibold text-slate-900">GARUDA Automated Forensic Intelligence Engine</span></div>
                          <div>Jurisdiction: <span className="font-semibold text-slate-900">Republic of India (CERT-In IT Directions 2022)</span></div>
                        </div>
                        <div className="text-right">
                          <div className="w-44 border-b border-slate-400 mb-1" />
                          <div>Authorized Forensic Investigator</div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <>
                      {/* Document Header */}
                      <div className="border-b-2 border-slate-900 pb-5 flex items-start justify-between">
                        <div>
                          <div className="text-xl font-black tracking-widest text-slate-950 uppercase">
                            GARUDA MAIL
                          </div>
                          <div className="text-[11px] tracking-wider text-slate-500 uppercase font-semibold">
                            Passive Email Cryptographic Forensics & Security Intelligence
                          </div>
                        </div>
                        <div className="text-right text-[11px] text-slate-500 font-mono">
                          <div>REPORT ID: {previewReport.id}</div>
                          <div>DATE: {formatDateTime(previewReport.generatedAt)}</div>
                          <div>INGESTION: {previewReport.analysisId}</div>
                        </div>
                      </div>

                      {/* Title & Exec Summary */}
                      <div className="space-y-2">
                        <h2 className="text-xl font-bold text-slate-950">
                          {previewReport.title}
                        </h2>
                        <p className="text-[13px] text-slate-700 leading-relaxed">
                          This formal forensic document summarizes the passive network inspection of enterprise email traffic. Analysis was conducted using deterministic protocol validation rules, X.509 certificate chain verification, and deep unsupervised anomaly detection.
                        </p>
                      </div>

                      {/* High Level Risk Metrics */}
                      <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 grid grid-cols-3 gap-4 text-center">
                        <div>
                          <div className="text-[11px] uppercase font-bold text-slate-500">Overall Risk Score</div>
                          <div className="text-2xl font-black text-rose-600">78 / 100</div>
                          <div className="text-[10px] text-rose-700 font-bold">HIGH RISK</div>
                        </div>
                        <div>
                          <div className="text-[11px] uppercase font-bold text-slate-500">Total Findings</div>
                          <div className="text-2xl font-black text-slate-900">17</div>
                          <div className="text-[10px] text-slate-600">3 Critical, 7 High</div>
                        </div>
                        <div>
                          <div className="text-[11px] uppercase font-bold text-slate-500">PFS Adoption</div>
                          <div className="text-2xl font-black text-emerald-600">91.4%</div>
                          <div className="text-[10px] text-emerald-700">227 Protected Flows</div>
                        </div>
                      </div>

                      {/* Critical Findings Table */}
                      <div className="space-y-2">
                        <h3 className="text-sm font-bold text-slate-950 uppercase tracking-wider">
                          Critical Security & Cryptographic Findings
                        </h3>
                        <table className="w-full text-left border-collapse text-[12px]">
                          <thead>
                            <tr className="border-b border-slate-300 text-[10px] font-bold uppercase text-slate-600">
                              <th className="py-2">Finding</th>
                              <th className="py-2">Severity</th>
                              <th className="py-2">Standard Violation</th>
                              <th className="py-2">Remediation Priority</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-200">
                            {mockFindings.map(f => (
                              <tr key={f.id} className="py-2">
                                <td className="py-2 font-medium text-slate-900">
                                  <span className="font-mono text-slate-500 mr-1.5">{f.id}</span>
                                  {f.title}
                                </td>
                                <td className="py-2">
                                  <span className="font-bold text-[10px] uppercase text-rose-600">{f.severity}</span>
                                </td>
                                <td className="py-2 text-slate-600 text-[11px]">
                                  {f.standardsMapping[0]?.standard || 'NIST SP 800-52r2'}
                                </td>
                                <td className="py-2 font-semibold text-slate-900">
                                  Immediate Action
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      {/* Attestation & Signature block */}
                      <div className="pt-6 border-t border-slate-300 flex items-end justify-between text-[11px] text-slate-600">
                        <div>
                          <div>Forensic Lead: <span className="font-semibold text-slate-900">Garuda Automated Analysis Agent</span></div>
                          <div>Verification SHA-256: <span className="font-mono text-[10px]">9f83ac58c26786a41f6e216...</span></div>
                        </div>
                        <div className="text-right">
                          <div className="w-40 border-b border-slate-400 mb-1" />
                          <div>Authorized Signature</div>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>

      </div>
    </AppShell>
  );
}
