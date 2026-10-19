'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Layers, Download, Shield, AlertTriangle, CheckCircle,
  FileCode, Filter, ExternalLink, Database, Sparkles, Copy, Check,
  GitBranch, Server, Terminal, Lock, Key, Radio
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { mockCbom } from '@/lib/mock/data';
import Link from 'next/link';
import clsx from 'clsx';
import type { CbomAsset } from '@/types';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function CbomPage() {
  const [viewMode, setViewMode] = useState<'table' | 'tree'>('table');
  const [filterRisk, setFilterRisk] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [exportNotification, setExportNotification] = useState<string | null>(null);

  const filteredAssets = mockCbom.filter((item) => {
    const matchesRisk = filterRisk === 'all' || item.risk === filterRisk;
    const matchesSearch =
      item.asset.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.cipher.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.protocol.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesRisk && matchesSearch;
  });

  const handleExport = (format: 'cyclonedx' | 'spdx' | 'csv') => {
    let content = '';
    let filename = '';
    let type = '';

    if (format === 'cyclonedx') {
      const cycloneDxSchema = {
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        version: 1,
        metadata: {
          timestamp: new Date().toISOString(),
          tools: [{ vendor: 'Garuda Mail', name: 'Cryptographic Forensic Engine', version: '2.4.0' }],
        },
        components: mockCbom.map((c) => ({
          type: 'cryptographic-asset',
          name: c.asset,
          properties: [
            { name: 'garuda:protocol', value: c.protocol },
            { name: 'garuda:tls-version', value: c.tlsVersion },
            { name: 'garuda:cipher-suite', value: c.cipher },
            { name: 'garuda:key-algorithm', value: c.keyAlgorithm },
            { name: 'garuda:key-size', value: String(c.keySize) },
            { name: 'garuda:risk', value: c.risk },
          ],
        })),
      };
      content = JSON.stringify(cycloneDxSchema, null, 2);
      filename = 'garuda-cbom-cyclonedx.json';
      type = 'application/json';
    } else if (format === 'csv') {
      const headers = 'Asset,Protocol,TLS Version,Cipher Suite,Key Algorithm,Key Size,Certificate,JA4,Risk\n';
      const rows = mockCbom.map(c => `"${c.asset}","${c.protocol}","${c.tlsVersion}","${c.cipher}","${c.keyAlgorithm}",${c.keySize},"${c.certificate || ''}","${c.ja4 || ''}","${c.risk}"`).join('\n');
      content = headers + rows;
      filename = 'garuda-cbom-inventory.csv';
      type = 'text/csv';
    } else {
      content = JSON.stringify({ spdxVersion: 'SPDX-3.0', packages: mockCbom }, null, 2);
      filename = 'garuda-cbom-spdx.json';
      type = 'application/json';
    }

    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    setExportNotification(`Exported ${filename} successfully!`);
    setTimeout(() => setExportNotification(null), 3000);
  };

  return (
    <AppShell
      title="Cryptographic Bill of Materials (CBOM)"
      description="CycloneDX 1.6 & NIST IR 8547 compliant inventory of enterprise email cryptographic assets and algorithms"
    >
      <div className="space-y-6">

        {/* ── Top Notification Banner ── */}
        {exportNotification && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-3 bg-[rgba(34,197,94,0.1)] border border-[rgba(34,197,94,0.3)] text-[var(--color-severity-healthy)] rounded-lg text-[13px] flex items-center gap-2"
          >
            <Check size={16} /> {exportNotification}
          </motion.div>
        )}

        {/* ── Summary & Export Bar ── */}
        <div className="card p-6 bg-gradient-to-r from-[rgba(56,189,248,0.06)] to-transparent border-[rgba(56,189,248,0.2)] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-[rgba(56,189,248,0.12)] border border-[rgba(56,189,248,0.25)] flex items-center justify-center text-[var(--color-accent)]">
              <Layers size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h3 className="text-lg font-bold text-[var(--color-text-primary)]">
                  Cryptographic Inventory & Bill of Materials
                </h3>
                <span className="badge-info text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                  CycloneDX 1.6
                </span>
              </div>
              <p className="text-[12px] text-[var(--color-text-muted)]">
                Structured machine-readable inventory of all asymmetric keys, ciphers, hash algorithms, and protocols
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleExport('cyclonedx')}
              className="btn btn-primary text-[12px] py-1.5 px-3 flex items-center gap-1.5"
            >
              <Download size={14} /> Export CycloneDX
            </button>
            <button
              onClick={() => handleExport('csv')}
              className="btn btn-secondary text-[12px] py-1.5 px-3 flex items-center gap-1.5"
            >
              <FileCode size={14} /> Export CSV
            </button>
          </div>
        </div>

        {/* ── Metrics Grid ── */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card p-5 space-y-1.5 border-t-2 border-t-sky-500/80 bg-gradient-to-b from-sky-500/[0.08] to-transparent shadow-lg shadow-sky-500/10 card-hover">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Inventoried Assets</span>
              <Database size={16} className="text-sky-400" />
            </div>
            <div className="text-3xl font-bold text-sky-400 tabular-nums">
              {mockCbom.length}
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">Tracked email server endpoints</p>
          </div>

          <div className="card p-5 space-y-1.5 border-t-2 border-t-purple-500/80 bg-gradient-to-b from-purple-500/[0.08] to-transparent shadow-lg shadow-purple-500/10 card-hover">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>PQC Migration Debt</span>
              <Sparkles size={16} className="text-purple-400" />
            </div>
            <div className="text-3xl font-bold text-purple-400 tabular-nums">
              100%
            </div>
            <p className="text-[11px] text-purple-400/90 font-medium">All 6 assets rely on classical RSA/ECC</p>
          </div>

          <div className="card p-5 space-y-1.5 border-t-2 border-t-rose-500/80 bg-gradient-to-b from-rose-500/[0.08] to-transparent shadow-lg shadow-rose-500/10 card-hover">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Non-Compliant Algorithms</span>
              <AlertTriangle size={16} className="text-rose-400" />
            </div>
            <div className="text-3xl font-bold text-rose-400 tabular-nums">
              {mockCbom.filter(c => c.risk === 'critical' || c.risk === 'high').length}
            </div>
            <p className="text-[11px] text-rose-400 font-medium">3DES, 1024-bit RSA, or TLS 1.0</p>
          </div>

          <div className="card p-5 space-y-1.5 border-t-2 border-t-emerald-500/80 bg-gradient-to-b from-emerald-500/[0.08] to-transparent shadow-lg shadow-emerald-500/10 card-hover">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Fully Compliant Assets</span>
              <CheckCircle size={16} className="text-emerald-400" />
            </div>
            <div className="text-3xl font-bold text-emerald-400 tabular-nums">
              {mockCbom.filter(c => c.risk === 'low').length}
            </div>
            <p className="text-[11px] text-emerald-400 font-medium">TLS 1.3 + AEAD ciphers</p>
          </div>
        </div>

        {/* ── View Mode Selector Bar ── */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setViewMode('table')}
              className={clsx(
                'px-3.5 py-1.5 rounded-lg text-[12px] font-semibold transition-all border flex items-center gap-1.5',
                viewMode === 'table'
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-sm'
                  : 'bg-[var(--color-surface-2)] text-[var(--color-text-muted)] border-transparent'
              )}
            >
              <Layers size={14} />
              <span>CycloneDX Inventory Table</span>
            </button>
            <button
              onClick={() => setViewMode('tree')}
              className={clsx(
                'px-3.5 py-1.5 rounded-lg text-[12px] font-semibold transition-all border flex items-center gap-1.5',
                viewMode === 'tree'
                  ? 'bg-purple-500/20 text-purple-300 border-purple-500/40 shadow-sm'
                  : 'bg-[var(--color-surface-2)] text-[var(--color-text-muted)] border-transparent'
              )}
            >
              <GitBranch size={14} />
              <span>Cryptographic Hierarchy Tree</span>
              <span className="text-[9px] px-1.5 py-0.2 rounded bg-purple-500/30 text-purple-200 font-mono font-bold">
                MAIL SERVER HIERARCHY
              </span>
            </button>
          </div>
          <span className="text-[11px] text-[var(--color-text-dim)] font-mono hidden sm:inline">
            NIST IR 8547 / CycloneDX 1.6
          </span>
        </div>

        {/* ── TREE VIEW: Cryptographic Hierarchy Tree ── */}
        {viewMode === 'tree' ? (
          <div className="card p-6 bg-gradient-to-b from-[var(--color-surface-1)] to-[var(--color-surface-2)] border border-[var(--color-border)] space-y-6 animate-in fade-in duration-200">
            <div className="flex items-center justify-between border-b border-[var(--color-border)] pb-3">
              <div className="flex items-center gap-2.5">
                <Server size={18} className="text-cyan-400" />
                <h4 className="text-base font-bold text-white">
                  MAIL SERVER CLUSTER: <span className="font-mono text-cyan-300">mail.sovereign.local</span>
                </h4>
              </div>
              <span className="badge-healthy text-[10px] px-2 py-0.5 rounded font-mono font-bold">
                4 ACTIVE PROTOCOL CHANNELS
              </span>
            </div>

            {/* Tree Branch Visual Representation */}
            <div className="space-y-5 font-mono text-[12px]">
              {/* Branch 1: SMTP / 587 */}
              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-emerald-500/30 space-y-2.5">
                <div className="flex items-center justify-between text-emerald-400 font-bold text-[13px]">
                  <span className="flex items-center gap-2">
                    <Radio size={14} /> ├── 🛡️ SMTP Submission (Port 587 / RFC 3207)
                  </span>
                  <span className="badge-healthy text-[10px] px-2 py-0.5 rounded uppercase">COMPLIANT (PQC HYBRID)</span>
                </div>
                <div className="pl-6 space-y-1 text-slate-300 text-[11px]">
                  <div>│   ├── 🔒 <b className="text-white">TLS 1.3 (RFC 8446)</b></div>
                  <div>│   │   ├── 🔑 Key Exchange: <span className="text-purple-300 font-bold">X25519MLKEM768 (NIST FIPS 203 Hybrid)</span></div>
                  <div>│   │   ├── 🔐 Symmetric Cipher: <span className="text-cyan-300">TLS_AES_256_GCM_SHA384 (Authenticated 256-bit AEAD)</span></div>
                  <div>│   │   ├── 📜 Hash Function: <span className="text-slate-300">SHA-384</span></div>
                  <div>│   │   └── 🏷️ Certificate: <span className="text-slate-200">CN=mail.sovereign.local (RSA 4096, Issuer: Garuda Sovereign Root CA)</span></div>
                  <div>│   └── 🛡️ Policy: <span className="text-emerald-400">MTA-STS mode:enforce + DANE TLSA 3 1 1 (DNSSEC Root Validated)</span></div>
                </div>
              </div>

              {/* Branch 2: SMTPS / 465 */}
              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-indigo-500/30 space-y-2.5">
                <div className="flex items-center justify-between text-indigo-400 font-bold text-[13px]">
                  <span className="flex items-center gap-2">
                    <Lock size={14} /> ├── 🛡️ SMTPS Implicit TLS (Port 465 / RFC 8314)
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-indigo-500/20 text-indigo-300">MODERN TLS 1.3</span>
                </div>
                <div className="pl-6 space-y-1 text-slate-300 text-[11px]">
                  <div>│   ├── 🔒 <b className="text-white">TLS 1.3</b></div>
                  <div>│   │   ├── 🔑 Key Exchange: <span className="text-slate-200">ECDHE-X25519 (Perfect Forward Secrecy)</span></div>
                  <div>│   │   ├── 🔐 Symmetric Cipher: <span className="text-indigo-300">TLS_CHACHA20_POLY1305_SHA256</span></div>
                  <div>│   │   └── 🏷️ Certificate: <span className="text-slate-200">CN=smtp.sovereign.local (ECDSA P-384)</span></div>
                </div>
              </div>

              {/* Branch 3: IMAP / 993 */}
              <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-sky-500/30 space-y-2.5">
                <div className="flex items-center justify-between text-sky-400 font-bold text-[13px]">
                  <span className="flex items-center gap-2">
                    <Terminal size={14} /> ├── 📥 IMAP4rev1 Sync (Port 993 / RFC 3501)
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-sky-500/20 text-sky-300">ACCEPTABLE TLS 1.2</span>
                </div>
                <div className="pl-6 space-y-1 text-slate-300 text-[11px]">
                  <div>│   ├── 🔒 <b className="text-white">TLS 1.2</b></div>
                  <div>│   │   ├── 🔑 Key Exchange: <span className="text-slate-200">ECDHE-P256 (Classical ECC)</span></div>
                  <div>│   │   ├── 🔐 Cipher: <span className="text-sky-300">ECDHE-RSA-AES128-GCM-SHA256</span></div>
                  <div>│   │   └── 🏷️ Certificate: <span className="text-slate-200">CN=imap.sovereign.local</span></div>
                </div>
              </div>

              {/* Branch 4: POP3 / 110 Legacy */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-rose-950/30 to-[var(--color-surface-2)] border border-rose-500/40 space-y-2.5">
                <div className="flex items-center justify-between text-rose-400 font-bold text-[13px]">
                  <span className="flex items-center gap-2">
                    <AlertTriangle size={14} /> └── ⚠️ POP3 Legacy Mail Service (Port 110 / RFC 1939)
                  </span>
                  <span className="badge-critical text-[10px] px-2 py-0.5 rounded font-bold uppercase">CRITICAL CVE-2016-2183</span>
                </div>
                <div className="pl-6 space-y-1 text-rose-300 text-[11px]">
                  <div>    └── ⚠️ <b className="text-rose-400">TLS 1.1 (DEPRECATED - RFC 8996 Violation)</b></div>
                  <div>        ├── ❌ Key Exchange: <span className="text-rose-400 font-bold">Static RSA (NO Forward Secrecy / PFS: None)</span></div>
                  <div>        ├── ❌ Cipher: <span className="text-rose-400 font-bold">TLS_RSA_WITH_3DES_EDE_CBC_SHA (Sweet32 Vulnerable)</span></div>
                  <div>        └── ❌ Certificate: <span className="text-rose-400 font-bold">CN=pop.internal.local (Self-signed, EXPIRED)</span></div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* ── Search & Filter Controls ── */}
            <div className="card p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
              <input
                type="text"
                placeholder="Search by asset hostname, cipher, protocol..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full sm:w-80 px-3 py-1.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] placeholder-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-accent)]"
              />

              <div className="flex items-center gap-1.5 bg-[var(--color-surface-2)] p-1 rounded-lg border border-[var(--color-border)]">
                {['all', 'critical', 'high', 'medium', 'low'].map((risk) => (
                  <button
                    key={risk}
                    onClick={() => setFilterRisk(risk)}
                    className={clsx(
                      'px-3 py-1 text-[11px] font-medium rounded-md capitalize transition-colors',
                      filterRisk === risk
                        ? 'bg-[var(--color-surface-3)] text-[var(--color-text-primary)] shadow-sm'
                        : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
                    )}
                  >
                    {risk}
                  </button>
                ))}
              </div>
            </div>

            {/* ── CBOM Inventory Table ── */}
            <div className="card overflow-hidden">
              <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-2)] text-[11px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                  <th className="py-3 px-4">Asset / Endpoint</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">TLS Version</th>
                  <th className="py-3 px-4">Negotiated Cipher Suite</th>
                  <th className="py-3 px-4">Key Algorithm & Size</th>
                  <th className="py-3 px-4">X.509 Certificate</th>
                  <th className="py-3 px-4">Risk Rating</th>
                  <th className="py-3 px-4 text-right">JA4 Fingerprint</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-subtle)]">
                {filteredAssets.map((item) => (
                  <tr key={item.id} className="hover:bg-[var(--color-surface-2)] transition-colors">
                    <td className="py-3.5 px-4 font-semibold text-[var(--color-text-primary)]">
                      <div className="flex items-center gap-2">
                        <Database size={15} className="text-[var(--color-accent)] flex-shrink-0" />
                        <div>
                          <div>{item.asset}</div>
                          <div className="text-[10px] text-mono text-[var(--color-text-dim)]">{item.id}</div>
                        </div>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-mono font-medium">
                      {item.protocol}
                    </td>
                    <td className="py-3.5 px-4 text-mono">
                      <span className={clsx(
                        'px-1.5 py-0.5 rounded text-[11px]',
                        item.tlsVersion === 'TLS 1.0' ? 'bg-[rgba(239,68,68,0.15)] text-[var(--color-severity-critical)] font-bold' :
                        item.tlsVersion === 'None' ? 'bg-[rgba(239,68,68,0.15)] text-[var(--color-severity-critical)] font-bold' :
                        item.tlsVersion === 'TLS 1.3' ? 'bg-[rgba(34,197,94,0.15)] text-[var(--color-severity-healthy)] font-bold' :
                        'bg-[var(--color-surface-3)] text-[var(--color-text-secondary)]'
                      )}>
                        {item.tlsVersion}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-mono text-[12px] text-[var(--color-text-secondary)]">
                      {item.cipher}
                    </td>
                    <td className="py-3.5 px-4 text-mono text-[12px]">
                      {item.keyAlgorithm !== 'N/A' ? (
                        <span className={clsx(
                          item.keySize < 2048 && item.keyAlgorithm === 'RSA' ? 'text-[var(--color-severity-critical)] font-bold' : 'text-[var(--color-text-primary)]'
                        )}>
                          {item.keyAlgorithm} ({item.keySize}-bit)
                        </span>
                      ) : (
                        <span className="text-[var(--color-text-dim)]">N/A</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-mono text-[12px]">
                      {item.certificate ? (
                        <Link href="/certificates" className="text-[var(--color-accent)] hover:underline">
                          {item.certificate}
                        </Link>
                      ) : (
                        <span className="text-[var(--color-severity-critical)] font-medium">None</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={item.risk} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 text-right text-mono text-[11px] text-[var(--color-text-dim)]">
                      {item.ja4 ? item.ja4.slice(0, 16) + '...' : 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </>
    )}

      </div>
    </AppShell>
  );
}
