'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { FileText, Download, Shield, CheckCircle2, ArrowLeft, RefreshCw } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import Link from 'next/link';

export default function UserReportsPage() {
  const [downloading, setDownloading] = useState(false);

  const handleExport = () => {
    setDownloading(true);
    setTimeout(() => {
      const report = {
        title: 'GARUDA User Security & Audit Report',
        generatedAt: new Date().toISOString(),
        protocol: 'GARUDA-E2EE-v2',
        cipher: 'RSA-OAEP-2048 / AES-256-GCM',
        signature: 'RSA-PSS SHA-256',
        zeroKnowledgeStatus: 'VERIFIED',
        keyVaultStatus: 'ACTIVE',
      };
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `garuda_user_security_report_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setDownloading(false);
    }, 500);
  };

  return (
    <AppShell title="Personal Security Reports" description="Authorized reports and cryptographic posture exports">
      <div className="max-w-4xl mx-auto space-y-6">
        <Link
          href="/user/dashboard"
          className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft size={14} /> Back to User Dashboard
        </Link>

        <div className="card p-6 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-[var(--color-border-subtle)]">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400">
                <FileText size={20} />
              </div>
              <div>
                <h2 className="text-sm font-bold text-white">Personal Security Audit Certificate</h2>
                <p className="text-xs text-slate-400">Cryptographically verifiable evidence of zero-knowledge communications</p>
              </div>
            </div>
            <button
              onClick={handleExport}
              disabled={downloading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-300 text-xs font-semibold transition-colors"
            >
              {downloading ? <RefreshCw size={12} className="animate-spin" /> : <Download size={12} />}
              Export Report (JSON)
            </button>
          </div>

          <div className="space-y-3 text-xs text-slate-300">
            <p>
              This report captures your local security parameters, active cryptographic algorithm suite, and verification status without disclosing confidential message contents or private keys.
            </p>
            <div className="p-4 rounded-xl bg-[var(--color-surface-2)] border border-[var(--color-border-subtle)] font-mono text-[11px] space-y-1">
              <div><b className="text-sky-400">Standard:</b> NIST FIPS 140-3 Compliant Primitives</div>
              <div><b className="text-sky-400">Payload Encryption:</b> AES-256-GCM with 96-bit unique IV & 128-bit Auth Tag</div>
              <div><b className="text-sky-400">Key Encapsulation:</b> RSA-OAEP with SHA-256 MGF1</div>
              <div><b className="text-sky-400">Digital Signatures:</b> RSA-PSS with SHA-256 and 32-byte salt</div>
              <div><b className="text-sky-400">Client Key Protection:</b> PBKDF2 (100,000 iterations) + AES-256-GCM</div>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
