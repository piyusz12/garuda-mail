'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  FlaskConical, Play, CheckCircle2, AlertTriangle, Shield,
  ArrowRight, RefreshCw, Cpu, Terminal, Radio, Sparkles,
  FileText, Download, Layers, Activity, Lock, AlertCircle
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge, RiskScore } from '@/components/ui/shared';
import clsx from 'clsx';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

type LabScenario = 'secure' | 'weak' | 'anomalous';

interface ScenarioProfile {
  id: LabScenario;
  name: string;
  badge: string;
  badgeColor: string;
  description: string;
  tlsVersion: string;
  cipher: string;
  keyExchange: string;
  certificate: string;
  mtaStsDane: string;
  ja4: string;
  anomalyScore: number;
  deterministicScore: number;
  contextScore: number;
  finalCrs: number;
  cvssSeverity: string;
  verdict: 'COMPLIANT' | 'CRITICAL_RISK' | 'BEHAVIORAL_ANOMALY';
  pcapPackets: number;
  trafficSample: string[];
}

const LAB_SCENARIOS: Record<LabScenario, ScenarioProfile> = {
  secure: {
    id: 'secure',
    name: 'Profile A: Hardened Post-Quantum Baseline (Secure)',
    badge: 'BENCHMARK SECURE',
    badgeColor: 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10',
    description: 'Compliant military-grade configuration: TLS 1.3, ML-KEM-768 hybrid key exchange, authenticated AES-256-GCM, valid X.509 chain, and enforced MTA-STS/DANE.',
    tlsVersion: 'TLS 1.3 (RFC 8446)',
    cipher: 'TLS_AES_256_GCM_SHA384',
    keyExchange: 'X25519MLKEM768 (RFC 10024 / FIPS 203 Hybrid)',
    certificate: 'Valid (RSA 4096 / SHA-384, CA: Garuda Sovereign Root)',
    mtaStsDane: 'MTA-STS mode:enforce | DANE TLSA 3 1 1 Verified',
    ja4: 't13d1516h2_8daaf6152771_b532bf1e9e8f (Standard Enterprise Client)',
    anomalyScore: 4,
    deterministicScore: 0,
    contextScore: 8,
    finalCrs: 5,
    cvssSeverity: 'None (0.0)',
    verdict: 'COMPLIANT',
    pcapPackets: 28,
    trafficSample: [
      '[00.001] PC-A:52410 > PC-B:587 [SYN]',
      '[00.002] PC-B:587 > PC-A:52410 [SYN, ACK]',
      '[00.003] PC-A:52410 > PC-B:587 [ACK] TCP handshake established',
      '[00.005] PC-A > PC-B TLS 1.3 ClientHello (supported_groups: 0x11ec X25519MLKEM768, key_share: ML-KEM-768)',
      '[00.009] PC-B > PC-A TLS 1.3 ServerHello (selected: TLS_AES_256_GCM_SHA384, group: 0x11ec)',
      '[00.012] PC-B > PC-A EncryptedExtensions, Certificate (CN=mail.sovereign.local), CertificateVerify',
      '[00.015] PC-A > PC-B Finished (Forward secrecy: Enforced, PQC: Active)',
      '[00.021] PC-A > PC-B ApplicationData (E2EE Encrypted MIME Payload - Zero Leaks)',
    ],
  },
  weak: {
    id: 'weak',
    name: 'Profile B: STRIPTLS & Legacy Deprecated Ciphers (Weak)',
    badge: 'ACTIVE ATTACK / VULNERABLE',
    badgeColor: 'border-rose-500/40 text-rose-400 bg-rose-500/10',
    description: 'Adversary-controlled downgrade: STRIPTLS forces plaintext SMTP fallback, or negotiates deprecated TLS 1.0 with static RSA and expired certificates.',
    tlsVersion: 'TLS 1.0 (RFC 2246 - Deprecated)',
    cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA (Sweet32 Vulnerable)',
    keyExchange: 'RSA Static Key Exchange (No Forward Secrecy / PFS: None)',
    certificate: 'EXPIRED 42 days ago (Self-Signed, CN mismatch)',
    mtaStsDane: 'Absent / STRIPTLS Suppressed (Zero MITM Defense)',
    ja4: 't10d030300_000000000000_3des00000000 (Obsolete Legacy Agent)',
    anomalyScore: 84,
    deterministicScore: 95,
    contextScore: 88,
    finalCrs: 92,
    cvssSeverity: 'Critical (9.4 - CVE-2016-2183 Sweet32)',
    verdict: 'CRITICAL_RISK',
    pcapPackets: 46,
    trafficSample: [
      '[00.001] PC-A:49182 > PC-B:25 [SYN]',
      '[00.002] PC-B:25 > PC-A:49182 [SYN, ACK]',
      '[00.003] PC-B < 220 relay.enterprise.local ESMTP Postfix',
      '[00.004] PC-A > EHLO client.lan',
      '[00.005] [MITM ALERT] Adversary intercepts and strips 250-STARTTLS advertisement from response!',
      '[00.006] PC-A falls back to deprecated TLS 1.0 ClientHello (Cipher: 3DES-EDE-CBC-SHA)',
      '[00.011] PC-B sends Certificate: EXPIRED (Expired 2026-08-30, Self-signed)',
      '[00.014] Handshake completed without Ephemeral Diffie-Hellman (PFS: None - Harvest-Now-Decrypt-Later target)',
      '[00.022] Cleartext credentials and email metadata exposed in flight!',
    ],
  },
  anomalous: {
    id: 'anomalous',
    name: 'Profile C: Novel JA4 & Covert Data Exfiltration (Anomalous)',
    badge: 'AI BEHAVIORAL OUTLIER',
    badgeColor: 'border-amber-500/40 text-amber-400 bg-amber-500/10',
    description: 'Cryptographically valid TLS 1.2 handshake, but AI ensemble detects rare non-browser JA4 signature, beaconing packet cadence, and covert burst exfiltration.',
    tlsVersion: 'TLS 1.2 (RFC 5246)',
    cipher: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    keyExchange: 'ECDHE-P256 (Classical ECC only, Quantum Vulnerable)',
    certificate: 'Valid (Let\'s Encrypt Authority, issued 4 days ago)',
    mtaStsDane: 'Testing mode (No strict enforcement)',
    ja4: 't12d190800_4917a10f8391_9821bb42f110 (Rare Custom Python/Go Scraper)',
    anomalyScore: 89,
    deterministicScore: 35,
    contextScore: 78,
    finalCrs: 76,
    cvssSeverity: 'Medium (6.2 - Suspicious Beaconing)',
    verdict: 'BEHAVIORAL_ANOMALY',
    pcapPackets: 184,
    trafficSample: [
      '[00.001] PC-A:38192 > PC-B:993 [SYN] (Periodic exactly every 60.000s - Beaconing signature)',
      '[00.002] PC-B:993 > PC-A:38192 [SYN, ACK]',
      '[00.004] PC-A > ClientHello (Rare Extension Ordering: novel GREASE + non-standard ALPN)',
      '[00.007] [AI DETECTION] JA4 Fingerprint frequency: 0.002% across 14,200 enterprise baseline sessions',
      '[00.012] Handshake establishes valid TLS 1.2 channel',
      '[00.018] [ANOMALY DETECTED] Immediate 12.8 MB burst upload within 140ms on port 993',
      '[00.025] High entropy payload: 7.94 / 8.00 (Indicators of encrypted archive exfiltration)',
      '[00.030] Isolation Forest + Autoencoder reconstruction error: 0.884 (Threshold: 0.120)',
    ],
  },
};

export default function GarudaLabPage() {
  const [selectedScenario, setSelectedScenario] = useState<LabScenario>('secure');
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulatedResults, setSimulatedResults] = useState<ScenarioProfile | null>(LAB_SCENARIOS.secure);
  const [compareMode, setCompareMode] = useState(true);

  const runSimulation = (scenarioId: LabScenario) => {
    setSelectedScenario(scenarioId);
    setIsSimulating(true);
    setTimeout(() => {
      setSimulatedResults(LAB_SCENARIOS[scenarioId]);
      setIsSimulating(false);
    }, 900);
  };

  const active = simulatedResults || LAB_SCENARIOS[selectedScenario];

  return (
    <AppShell
      title="GARUDA LAB — Cryptographic Attack & Validation Testbed"
      description="Two-PC reproducible laboratory for controlled injection and comparative analysis of Secure vs Weak vs Anomalous email captures"
    >
      <div className="space-y-6">

        {/* ── Top Header Banner with Architecture Overview ── */}
        <div className="card p-5 bg-gradient-to-r from-blue-950/30 via-[var(--color-surface-2)] to-purple-950/20 border border-blue-500/20 space-y-3">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <FlaskConical size={22} />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">GARUDA LAB Simulation Environment</h3>
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                    2-PC TESTBED REPRODUCIBLE
                  </span>
                </div>
                <p className="text-[12px] text-[var(--color-text-muted)]">
                  Simulate and validate live packet captures across PC-A (Mail Agent) ↔ PC-B (Sovereign MX Relay). Evaluates Post-Quantum readiness, STRIPTLS downgrade detection, and AI behavioral anomalies.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setCompareMode(!compareMode)}
                className={clsx(
                  'px-3 py-1.5 rounded-lg text-[12px] font-semibold border transition-all flex items-center gap-1.5',
                  compareMode
                    ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                    : 'bg-[var(--color-surface-3)] text-[var(--color-text-muted)] border-[var(--color-border-subtle)]'
                )}
              >
                <Layers size={13} />
                <span>{compareMode ? '3-Way Comparison View' : 'Single Profile Focus'}</span>
              </button>
            </div>
          </div>

          {/* Quick Scenario Launch Buttons */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
            {(['secure', 'weak', 'anomalous'] as LabScenario[]).map(sc => {
              const profile = LAB_SCENARIOS[sc];
              const isCurrent = selectedScenario === sc;
              return (
                <button
                  key={sc}
                  type="button"
                  onClick={() => runSimulation(sc)}
                  disabled={isSimulating}
                  className={clsx(
                    'p-3.5 rounded-xl text-left border transition-all relative overflow-hidden',
                    isCurrent
                      ? 'border-cyan-500/60 bg-gradient-to-br from-cyan-950/40 to-[var(--color-surface-2)] shadow-lg shadow-cyan-500/10 ring-1 ring-cyan-500/40'
                      : 'border-[var(--color-border)] bg-[var(--color-surface-1)] hover:border-slate-600'
                  )}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className={clsx('text-[10px] px-2 py-0.5 rounded font-mono font-bold border', profile.badgeColor)}>
                      {profile.badge}
                    </span>
                    <span className="text-[11px] font-mono font-bold text-slate-300">
                      CRS: {profile.finalCrs}/100
                    </span>
                  </div>
                  <div className="font-bold text-[13px] text-white truncate">{profile.name.split(':')[1] || profile.name}</div>
                  <div className="text-[11px] text-[var(--color-text-dim)] truncate mt-0.5">{profile.tlsVersion} • {profile.cipher.slice(0, 24)}...</div>
                  {isCurrent && (
                    <div className="absolute top-2 right-2 flex items-center gap-1 text-[10px] font-bold text-cyan-400">
                      <Radio size={10} className="animate-pulse" />
                      ACTIVE
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* ── Comparative Side-by-Side Matrix (When compareMode is active) ── */}
        {compareMode && (
          <div className="card p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
              <div className="flex items-center gap-2">
                <Layers size={16} className="text-purple-400" />
                <h4 className="text-sm font-bold text-white">Controlled Lab Comparative Matrix (Secure vs Weak vs Anomalous)</h4>
              </div>
              <span className="text-[11px] text-[var(--color-text-dim)] font-mono">
                Reproducible Jury Test Protocol
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-[12px]">
                <thead>
                  <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-2)] text-[11px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                    <th className="py-2.5 px-3">Evaluation Parameter</th>
                    <th className="py-2.5 px-3 text-emerald-400">Profile A: Secure (ML-KEM)</th>
                    <th className="py-2.5 px-3 text-rose-400">Profile B: Weak (STRIPTLS)</th>
                    <th className="py-2.5 px-3 text-amber-400">Profile C: Anomalous (JA4 Outlier)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border-subtle)] font-mono">
                  <tr>
                    <td className="py-2.5 px-3 font-sans font-semibold text-[var(--color-text-primary)]">TLS Protocol Version</td>
                    <td className="py-2.5 px-3 text-emerald-300 font-bold">TLS 1.3 (RFC 8446)</td>
                    <td className="py-2.5 px-3 text-rose-400 font-bold">TLS 1.0 (Deprecated)</td>
                    <td className="py-2.5 px-3 text-slate-300">TLS 1.2</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 font-sans font-semibold text-[var(--color-text-primary)]">Negotiated Cipher</td>
                    <td className="py-2.5 px-3 text-emerald-300">TLS_AES_256_GCM_SHA384</td>
                    <td className="py-2.5 px-3 text-rose-400">TLS_RSA_3DES_EDE_CBC_SHA</td>
                    <td className="py-2.5 px-3 text-slate-300">ECDHE_RSA_AES128_GCM</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 font-sans font-semibold text-[var(--color-text-primary)]">Key Exchange & PQC</td>
                    <td className="py-2.5 px-3 text-emerald-300">X25519MLKEM768 (PQC Hybrid)</td>
                    <td className="py-2.5 px-3 text-rose-400">Static RSA (No PFS)</td>
                    <td className="py-2.5 px-3 text-slate-300">ECDHE-P256 (Classical only)</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 font-sans font-semibold text-[var(--color-text-primary)]">MTA-STS & DANE Defense</td>
                    <td className="py-2.5 px-3 text-emerald-300">mode:enforce + DANE TLSA</td>
                    <td className="py-2.5 px-3 text-rose-400">STRIPTLS Cleartext Fallback</td>
                    <td className="py-2.5 px-3 text-amber-300">mode:testing</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 font-sans font-semibold text-[var(--color-text-primary)]">JA4 Client Fingerprint</td>
                    <td className="py-2.5 px-3 text-slate-300">t13d1516h2 (Standard)</td>
                    <td className="py-2.5 px-3 text-rose-400">t10d030300 (Obsolete)</td>
                    <td className="py-2.5 px-3 text-amber-300 font-bold">t12d190800 (Rare Outlier: 0.002%)</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 font-sans font-semibold text-[var(--color-text-primary)]">Deterministic Rule Score</td>
                    <td className="py-2.5 px-3 text-emerald-300 font-bold">0 / 100</td>
                    <td className="py-2.5 px-3 text-rose-400 font-bold">95 / 100 (Critical)</td>
                    <td className="py-2.5 px-3 text-slate-300 font-bold">35 / 100</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 px-3 font-sans font-semibold text-[var(--color-text-primary)]">AI Anomaly Outlier Score</td>
                    <td className="py-2.5 px-3 text-emerald-300 font-bold">4 / 100</td>
                    <td className="py-2.5 px-3 text-slate-300 font-bold">84 / 100</td>
                    <td className="py-2.5 px-3 text-amber-300 font-bold">89 / 100 (Unusual Burst)</td>
                  </tr>
                  <tr className="bg-[var(--color-surface-2)]">
                    <td className="py-2.5 px-3 font-sans font-bold text-white">Final GARUDA CRS (Risk Score)</td>
                    <td className="py-2.5 px-3 text-emerald-400 font-black text-sm">CRS: 5 (Healthy)</td>
                    <td className="py-2.5 px-3 text-rose-400 font-black text-sm">CRS: 92 (Critical)</td>
                    <td className="py-2.5 px-3 text-amber-400 font-black text-sm">CRS: 76 (High Anomaly)</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Active Lab Profile Inspection ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Detailed Scorecards (1 Col) */}
          <div className="space-y-4">
            <div className="card p-5 space-y-3 border-t-2 border-t-cyan-400 bg-gradient-to-b from-cyan-950/20 to-transparent">
              <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
                <span>Selected Active Profile</span>
                <FlaskConical size={14} className="text-cyan-400" />
              </div>
              <h4 className="text-base font-bold text-white">{active.name}</h4>
              <p className="text-[12px] text-[var(--color-text-secondary)] leading-relaxed">
                {active.description}
              </p>

              <div className="pt-2 border-t border-[var(--color-border)] space-y-2 text-[12px]">
                <div className="flex items-center justify-between">
                  <span className="text-[var(--color-text-dim)]">GARUDA CRS:</span>
                  <span className="font-mono font-bold text-cyan-300 text-sm">{active.finalCrs}/100</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[var(--color-text-dim)]">CVSS v4.0 Base Severity:</span>
                  <span className="font-mono text-slate-300">{active.cvssSeverity}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[var(--color-text-dim)]">Verdict:</span>
                  <span className={clsx('font-mono font-bold text-[11px] px-2 py-0.5 rounded', active.badgeColor)}>
                    {active.verdict}
                  </span>
                </div>
              </div>
            </div>

            {/* Hybrid Risk Fusion Breakdown */}
            <div className="card p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-2 text-[12px] font-semibold text-white">
                <div className="flex items-center gap-1.5">
                  <Cpu size={14} className="text-indigo-400" />
                  <span>Hybrid Risk Fusion Composition</span>
                </div>
                <span className="text-[10px] text-cyan-400 font-mono">Confidence: 97%</span>
              </div>
              <div className="space-y-2 text-[11px]">
                <div>
                  <div className="flex justify-between text-[var(--color-text-muted)] mb-1">
                    <span>Deterministic Crypto Rule Score:</span>
                    <b className="font-mono text-slate-200">{active.deterministicScore}%</b>
                  </div>
                  <div className="h-1.5 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
                    <div className="h-full bg-rose-500 rounded-full" style={{ width: `${active.deterministicScore}%` }} />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-[var(--color-text-muted)] mb-1">
                    <span>AI Behavioral Anomaly Outlier:</span>
                    <b className="font-mono text-slate-200">{active.anomalyScore}%</b>
                  </div>
                  <div className="h-1.5 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
                    <div className="h-full bg-amber-500 rounded-full" style={{ width: `${active.anomalyScore}%` }} />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-[var(--color-text-muted)] mb-1">
                    <span>Asset Sensitivity & Threat Context:</span>
                    <b className="font-mono text-slate-200">{active.contextScore}%</b>
                  </div>
                  <div className="h-1.5 bg-[var(--color-surface-3)] rounded-full overflow-hidden">
                    <div className="h-full bg-sky-500 rounded-full" style={{ width: `${active.contextScore}%` }} />
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Simulated PCAP Traffic & Transcript Stream (2 Cols) */}
          <div className="lg:col-span-2 card p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
              <div className="flex items-center gap-2">
                <Terminal size={16} className="text-cyan-400" />
                <h4 className="text-sm font-bold text-white">Live Synthetic PCAP Packet Stream (PC-A ↔ PC-B)</h4>
              </div>
              <div className="flex items-center gap-2 text-[11px] font-mono text-[var(--color-text-dim)]">
                <span>{active.pcapPackets} Captured Packets</span>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              </div>
            </div>

            <div className="p-3 bg-[var(--color-surface-2)] rounded-lg font-mono text-[11px] space-y-2 border border-[var(--color-border-subtle)] max-h-[380px] overflow-y-auto">
              {active.trafficSample.map((line, idx) => (
                <div
                  key={idx}
                  className={clsx(
                    'p-1.5 rounded transition-colors',
                    line.includes('[MITM ALERT]') || line.includes('Vulnerable') || line.includes('EXPIRED')
                      ? 'bg-rose-500/15 text-rose-300 font-bold border-l-2 border-rose-500'
                      : line.includes('[AI DETECTION]') || line.includes('[ANOMALY')
                      ? 'bg-amber-500/15 text-amber-300 font-bold border-l-2 border-amber-500'
                      : line.includes('ML-KEM') || line.includes('PQC: Active') || line.includes('Zero Leaks')
                      ? 'bg-emerald-500/15 text-emerald-300 font-bold border-l-2 border-emerald-500'
                      : 'text-slate-300 hover:bg-slate-800/50'
                  )}
                >
                  {line}
                </div>
              ))}
            </div>

            <div className="pt-2 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-[11px] text-[var(--color-text-dim)]">
              <span>PCAP File Reference: <code className="text-cyan-300 font-mono">garuda-lab-{active.id}-capture.pcap</code></span>
              <button
                type="button"
                onClick={() => alert(`Downloaded forensic PCAP evidence for Profile: ${active.id}`)}
                className="flex items-center gap-1 text-[11px] text-cyan-400 hover:underline"
              >
                <Download size={12} />
                <span>Export Synthetic PCAP</span>
              </button>
            </div>
          </div>
        </div>

      </div>
    </AppShell>
  );
}
