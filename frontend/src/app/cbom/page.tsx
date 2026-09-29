'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Layers, Download, Shield, AlertTriangle, CheckCircle,
  FileCode, Filter, ExternalLink, Database, Sparkles, Copy, Check
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { SeverityBadge } from '@/components/ui/shared';
import { mockCbom } from '@/lib/mock/data';
import Link from 'next/link';
import clsx from 'clsx';
import type { CbomAsset } from '@/types';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function CbomPage() {
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
          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Inventoried Assets</span>
              <Database size={16} className="text-[var(--color-accent)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-text-primary)] tabular-nums">
              {mockCbom.length}
            </div>
            <p className="text-[11px] text-[var(--color-text-dim)]">Tracked email server endpoints</p>
          </div>

          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>PQC Migration Debt</span>
              <Sparkles size={16} className="text-[var(--color-severity-critical)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-critical)] tabular-nums">
              100%
            </div>
            <p className="text-[11px] text-[var(--color-severity-critical)] font-medium">All 6 assets rely on classical RSA/ECC</p>
          </div>

          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Non-Compliant Algorithms</span>
              <AlertTriangle size={16} className="text-[var(--color-severity-high)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-high)] tabular-nums">
              {mockCbom.filter(c => c.risk === 'critical' || c.risk === 'high').length}
            </div>
            <p className="text-[11px] text-[var(--color-severity-high)] font-medium">3DES, 1024-bit RSA, or TLS 1.0</p>
          </div>

          <div className="card p-5 space-y-1.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Fully Compliant Assets</span>
              <CheckCircle size={16} className="text-[var(--color-severity-healthy)]" />
            </div>
            <div className="text-3xl font-bold text-[var(--color-severity-healthy)] tabular-nums">
              {mockCbom.filter(c => c.risk === 'low').length}
            </div>
            <p className="text-[11px] text-[var(--color-severity-healthy)] font-medium">TLS 1.3 + AEAD ciphers</p>
          </div>
        </div>

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

      </div>
    </AppShell>
  );
}
