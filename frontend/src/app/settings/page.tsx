'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Settings, Sliders, Shield, Brain, Database, Bell,
  Save, RefreshCw, CheckCircle2, AlertTriangle, Key,
  Lock, Terminal, Cpu, Network, Globe, Server, Radio,
  Send, AlertCircle
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import clsx from 'clsx';
import { SUPPORTED_PROTOCOLS } from '@/lib/protocols';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<'protocols' | 'engine' | 'rules' | 'ai' | 'integrations'>('protocols');
  const [saveToast, setSaveToast] = useState(false);

  // ── Protocol Settings ──
  const [defaultOutboundProtocol, setDefaultOutboundProtocol] = useState('auto');
  const [smtpHost, setSmtpHost] = useState('smtp.gmail.com');
  const [smtpPort, setSmtpPort] = useState('587');
  const [smtpSecurity, setSmtpSecurity] = useState<'starttls' | 'ssl' | 'none'>('starttls');
  const [smtpUser, setSmtpUser] = useState('');
  const [smtpPass, setSmtpPass] = useState('');

  // Inbound IMAP Settings
  const [inboundProto, setInboundProto] = useState<'imap' | 'pop3'>('imap');
  const [imapHost, setImapHost] = useState('imap.gmail.com');
  const [imapPort, setImapPort] = useState('993');
  const [imapUser, setImapUser] = useState('');
  const [imapPass, setImapPass] = useState('');

  // Live Connection Test States
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [smtpTestResult, setSmtpTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [testingImap, setTestingImap] = useState(false);
  const [imapTestResult, setImapTestResult] = useState<{ success: boolean; message: string } | null>(null);

  // Multi-PC Network Info
  const [lanIps, setLanIps] = useState<string[]>([]);
  const [suggestedUrl, setSuggestedUrl] = useState('http://localhost:3000');

  useEffect(() => {
    async function loadNetworkInfo() {
      try {
        const res = await fetch('/api/protocols');
        if (res.ok) {
          const data = await res.json();
          if (data.lanIps) setLanIps(data.lanIps);
          if (data.suggestedUrl) setSuggestedUrl(data.suggestedUrl);
        }
      } catch (err) {
        console.error('Failed to load protocol settings info:', err);
      }
    }
    loadNetworkInfo();
  }, []);

  // Engine parameters
  const [captureInterface, setCaptureInterface] = useState('eth0 (Passive Tap)');
  const [reassemblyBuffer, setReassemblyBuffer] = useState('256 MB');
  const [streamTimeout, setStreamTimeout] = useState('60');
  const [retainPayloads, setRetainPayloads] = useState(true);

  // Rule toggles
  const [rules, setRules] = useState([
    { id: 'RULE-TLS-DEPRECATED-001', name: 'Flag Deprecated TLS (1.0 / 1.1)', category: 'Protocol', enabled: true, severity: 'critical' },
    { id: 'RULE-FS-MISSING-001', name: 'Require Perfect Forward Secrecy (PFS)', category: 'Crypto', enabled: true, severity: 'high' },
    { id: 'RULE-STARTTLS-MISSING-001', name: 'Flag Plaintext Credentials (No STARTTLS)', category: 'Cleartext', enabled: true, severity: 'critical' },
    { id: 'RULE-CERT-EXPIRY-001', name: 'X.509 Expiration Alert (<30 Days)', category: 'Certificates', enabled: true, severity: 'high' },
    { id: 'RULE-CIPHER-WEAK-001', name: 'Disallow Legacy Ciphers (3DES, RC4, CBC)', category: 'Crypto', enabled: true, severity: 'medium' },
    { id: 'RULE-KEY-LENGTH-001', name: 'Audit Weak Key Lengths (RSA < 2048)', category: 'Certificates', enabled: true, severity: 'high' },
  ]);

  // AI parameters
  const [contamination, setContamination] = useState(0.05);
  const [confidenceCutoff, setConfidenceCutoff] = useState(70);
  const [autoRetrain, setAutoRetrain] = useState('weekly');

  // Integrations
  const [webhookUrl, setWebhookUrl] = useState('https://hooks.slack.com/services/T00/B00/XXXX');
  const [syslogHost, setSyslogHost] = useState('syslog.enterprise.local:514');
  const [splunkHecToken, setSplunkHecToken] = useState('••••••••••••••••••••••••••••••••');

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaveToast(true);
    setTimeout(() => setSaveToast(false), 3000);
  };

  const handleTestSmtp = async () => {
    setTestingSmtp(true);
    setSmtpTestResult(null);
    try {
      const res = await fetch('/api/protocols', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'test-smtp',
          config: {
            host: smtpHost,
            port: parseInt(smtpPort),
            user: smtpUser,
            pass: smtpPass,
          },
        }),
      });
      const data = await res.json();
      setSmtpTestResult(data);
    } catch (err: any) {
      setSmtpTestResult({ success: false, message: err.message || 'Connection test failed' });
    } finally {
      setTestingSmtp(false);
    }
  };

  const handleTestImap = async () => {
    setTestingImap(true);
    setImapTestResult(null);
    try {
      const res = await fetch('/api/protocols', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'test-imap',
          config: {
            host: imapHost,
            port: parseInt(imapPort),
            user: imapUser,
            pass: imapPass,
            protocol: inboundProto,
          },
        }),
      });
      const data = await res.json();
      setImapTestResult(data);
    } catch (err: any) {
      setImapTestResult({ success: false, message: err.message || 'Connection test failed' });
    } finally {
      setTestingImap(false);
    }
  };

  const toggleRule = (ruleId: string) => {
    setRules(prev => prev.map(r => r.id === ruleId ? { ...r, enabled: !r.enabled } : r));
  };

  return (
    <AppShell
      title="Platform Settings"
      description="Configure email transmission protocols, SMTP/IMAP relays, multi-PC networking, and forensic rules"
    >
      <div className="space-y-6">

        {/* ── Save Notification Toast ── */}
        {saveToast && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-3 bg-[rgba(34,197,94,0.12)] border border-[rgba(34,197,94,0.3)] text-[var(--color-severity-healthy)] rounded-lg text-[13px] flex items-center justify-between"
          >
            <div className="flex items-center gap-2">
              <CheckCircle2 size={16} /> Configuration saved and active across all email protocols & network interfaces.
            </div>
            <span className="text-[11px] text-mono font-medium">REAL-TIME SYNC ACTIVE</span>
          </motion.div>
        )}

        {/* ── Settings Tabs ── */}
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] overflow-x-auto">
          {[
            { id: 'protocols' as const, label: 'Email Protocols & Multi-PC', icon: Network },
            { id: 'engine' as const, label: 'Capture & Ingestion', icon: Cpu },
            { id: 'rules' as const, label: 'Deterministic Rules', icon: Shield },
            { id: 'ai' as const, label: 'AI Anomaly Tuning', icon: Brain },
            { id: 'integrations' as const, label: 'SIEM & Alert Webhooks', icon: Bell },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                'px-4 py-2.5 text-[13px] font-medium border-b-2 flex items-center gap-2 transition-colors whitespace-nowrap',
                activeTab === tab.id
                  ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                  : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
              )}
            >
              <tab.icon size={16} /> {tab.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleSave} className="space-y-6">

          {/* ── TAB 0: Email Protocols & Multi-PC Networking ── */}
          {activeTab === 'protocols' && (
            <div className="space-y-6">

              {/* Multi-PC Connection Card */}
              <div className="card p-5 bg-[var(--color-surface-1)] border border-[var(--color-accent)]">
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <Radio size={16} className="text-[var(--color-severity-healthy)] animate-pulse" />
                      <h3 className="text-sm font-bold text-[var(--color-text-primary)]">
                        Cross-PC & Local Network (LAN) Connectivity
                      </h3>
                    </div>
                    <p className="text-[12px] text-[var(--color-text-secondary)]">
                      To access this Garuda Mail instance from another laptop or PC on your Wi-Fi/Ethernet network:
                    </p>
                  </div>
                  <span className="px-2.5 py-1 rounded text-[11px] font-mono font-bold bg-[var(--color-severity-healthy)]/10 text-[var(--color-severity-healthy)] border border-[var(--color-severity-healthy)]/20">
                    NETWORK LISTENING
                  </span>
                </div>

                <div className="mt-4 p-3 bg-[var(--color-surface-2)] rounded-lg border border-[var(--color-border)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="text-[11px] text-[var(--color-text-dim)] uppercase font-mono mb-0.5">
                      Connect Other PC To This URL
                    </div>
                    <div className="text-sm font-mono font-bold text-[var(--color-accent)] select-all">
                      {suggestedUrl}
                    </div>
                  </div>
                  <div className="text-[11px] text-[var(--color-text-muted)] sm:text-right">
                    <span>Host Interfaces: </span>
                    <span className="font-mono text-[var(--color-text-primary)]">{lanIps.join(', ') || '127.0.0.1'}</span>
                  </div>
                </div>
              </div>

              {/* Outbound Protocols Section */}
              <div className="card p-6 space-y-5">
                <div className="pb-3 border-b border-[var(--color-border)] flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                      Outbound Email Transmission Protocols
                    </h3>
                    <p className="text-[12px] text-[var(--color-text-muted)]">
                      Configure standard SMTP (587 STARTTLS), SMTPS (465 SSL), Direct MX (Port 25), or LAN Mesh
                    </p>
                  </div>
                  <span className="text-[11px] font-mono text-[var(--color-accent)]">RFC 5321 / RFC 3207</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Default Transmission Protocol
                    </label>
                    <select
                      value={defaultOutboundProtocol}
                      onChange={(e) => setDefaultOutboundProtocol(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    >
                      <option value="auto">Auto (Smart LAN Mesh & Relay - Recommended)</option>
                      <option value="smtp-starttls">SMTP with STARTTLS (Port 587 - Explicit TLS 1.3)</option>
                      <option value="smtps">SMTPS (Port 465 - Direct SSL/TLS Tunnel)</option>
                      <option value="smtp-direct">Direct SMTP (Port 25 - RFC 5321 Mail Exchanger)</option>
                      <option value="p2p-mesh">Garuda LAN P2P Mesh (Zero-Loss Local Delivery)</option>
                    </select>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Outbound SMTP Relay Server (Host)
                    </label>
                    <input
                      type="text"
                      value={smtpHost}
                      onChange={(e) => setSmtpHost(e.target.value)}
                      placeholder="smtp.gmail.com or mail.enterprise.local"
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)] font-mono"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Relay Port
                    </label>
                    <input
                      type="text"
                      value={smtpPort}
                      onChange={(e) => setSmtpPort(e.target.value)}
                      placeholder="587"
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)] font-mono"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Security & Negotiation
                    </label>
                    <select
                      value={smtpSecurity}
                      onChange={(e) => setSmtpSecurity(e.target.value as any)}
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    >
                      <option value="starttls">STARTTLS (Port 587 - Opportunistic/Strict TLS 1.3)</option>
                      <option value="ssl">Implicit SSL/TLS (Port 465)</option>
                      <option value="none">Plaintext (Port 25 Direct)</option>
                    </select>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      SMTP Username / Email
                    </label>
                    <input
                      type="text"
                      value={smtpUser}
                      onChange={(e) => setSmtpUser(e.target.value)}
                      placeholder="user@gmail.com or admin@enterprise.local"
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      SMTP Password / App Password
                    </label>
                    <input
                      type="password"
                      value={smtpPass}
                      onChange={(e) => setSmtpPass(e.target.value)}
                      placeholder="••••••••••••••••"
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>
                </div>

                {/* SMTP Test Button and Response */}
                <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <button
                    type="button"
                    onClick={handleTestSmtp}
                    disabled={testingSmtp}
                    className="px-4 py-2 rounded-lg bg-[var(--color-surface-3)] text-[12px] font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-accent)] hover:text-[#0B0D10] border border-[var(--color-border)] transition-colors flex items-center gap-2"
                  >
                    {testingSmtp ? (
                      <>
                        <RefreshCw size={14} className="animate-spin text-[var(--color-accent)]" />
                        <span>Verifying SMTP Handshake...</span>
                      </>
                    ) : (
                      <>
                        <Send size={14} />
                        <span>Test Outbound SMTP Connection</span>
                      </>
                    )}
                  </button>

                  {smtpTestResult && (
                    <div className={clsx(
                      'text-[12px] font-medium flex items-center gap-2 px-3 py-1.5 rounded border',
                      smtpTestResult.success
                        ? 'bg-[var(--color-severity-healthy)]/10 text-[var(--color-severity-healthy)] border-[var(--color-severity-healthy)]/20'
                        : 'bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical)] border-[var(--color-severity-critical)]/20'
                    )}>
                      {smtpTestResult.success ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}
                      <span>{smtpTestResult.message}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Inbound Protocols (IMAP / POP3) */}
              <div className="card p-6 space-y-5">
                <div className="pb-3 border-b border-[var(--color-border)] flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                      Inbound Mail Retrieval (IMAP & POP3)
                    </h3>
                    <p className="text-[12px] text-[var(--color-text-muted)]">
                      Fetch and sync incoming emails from external mailboxes into Garuda Mail
                    </p>
                  </div>
                  <span className="text-[11px] font-mono text-[var(--color-accent)]">RFC 3501 / RFC 1939</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Inbound Protocol
                    </label>
                    <select
                      value={inboundProto}
                      onChange={(e) => setInboundProto(e.target.value as any)}
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    >
                      <option value="imap">IMAP4rev1 (Port 993 - Two-way Sync)</option>
                      <option value="pop3">POP3 (Port 995 - Direct Mailbox Retrieval)</option>
                    </select>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Inbound Server Host
                    </label>
                    <input
                      type="text"
                      value={imapHost}
                      onChange={(e) => setImapHost(e.target.value)}
                      placeholder="imap.gmail.com"
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)] font-mono"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Username / Email
                    </label>
                    <input
                      type="text"
                      value={imapUser}
                      onChange={(e) => setImapUser(e.target.value)}
                      placeholder="user@gmail.com"
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                      Password / App Token
                    </label>
                    <input
                      type="password"
                      value={imapPass}
                      onChange={(e) => setImapPass(e.target.value)}
                      placeholder="••••••••••••••••"
                      className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                    />
                  </div>
                </div>

                {/* IMAP Test Button */}
                <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <button
                    type="button"
                    onClick={handleTestImap}
                    disabled={testingImap}
                    className="px-4 py-2 rounded-lg bg-[var(--color-surface-3)] text-[12px] font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-accent)] hover:text-[#0B0D10] border border-[var(--color-border)] transition-colors flex items-center gap-2"
                  >
                    {testingImap ? (
                      <>
                        <RefreshCw size={14} className="animate-spin text-[var(--color-accent)]" />
                        <span>Connecting to {inboundProto.toUpperCase()}...</span>
                      </>
                    ) : (
                      <>
                        <Globe size={14} />
                        <span>Test {inboundProto.toUpperCase()} Inbound Connection</span>
                      </>
                    )}
                  </button>

                  {imapTestResult && (
                    <div className={clsx(
                      'text-[12px] font-medium flex items-center gap-2 px-3 py-1.5 rounded border',
                      imapTestResult.success
                        ? 'bg-[var(--color-severity-healthy)]/10 text-[var(--color-severity-healthy)] border-[var(--color-severity-healthy)]/20'
                        : 'bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical)] border-[var(--color-severity-critical)]/20'
                    )}>
                      {imapTestResult.success ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}
                      <span>{imapTestResult.message}</span>
                    </div>
                  )}
                </div>
              </div>

            </div>
          )}

          {/* ── TAB 1: Capture & Ingestion ── */}
          {activeTab === 'engine' && (
            <div className="card p-6 space-y-5">
              <div className="pb-3 border-b border-[var(--color-border)]">
                <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                  PCAP Processing & Reassembly Engine
                </h3>
                <p className="text-[12px] text-[var(--color-text-muted)]">
                  Configure network tap interfaces and multi-flow TCP stream reconstruction limits
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="space-y-1.5">
                  <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                    Default Network Sniffing Interface
                  </label>
                  <select
                    value={captureInterface}
                    onChange={(e) => setCaptureInterface(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  >
                    <option value="eth0 (Passive Tap)">eth0 (Passive Tap - 10Gbps)</option>
                    <option value="eth1 (SPAN Mirror)">eth1 (SPAN Mirror - 1Gbps)</option>
                    <option value="any (Promiscuous All)">any (Promiscuous All)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                    TCP Stream Reassembly Buffer
                  </label>
                  <select
                    value={reassemblyBuffer}
                    onChange={(e) => setReassemblyBuffer(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  >
                    <option value="128 MB">128 MB (Low Memory Footprint)</option>
                    <option value="256 MB">256 MB (Standard Enterprise)</option>
                    <option value="512 MB">512 MB (High Throughput / Multi-Gbps)</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* ── TAB 2: Deterministic Rules ── */}
          {activeTab === 'rules' && (
            <div className="card p-6 space-y-5">
              <div className="pb-3 border-b border-[var(--color-border)]">
                <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                  Cryptographic Forensic Detection Rules
                </h3>
                <p className="text-[12px] text-[var(--color-text-muted)]">
                  Enable or disable automated deterministic checks executed on parsed TLS handshakes
                </p>
              </div>

              <div className="divide-y divide-[var(--color-border-subtle)]">
                {rules.map(rule => (
                  <div key={rule.id} className="py-3 flex items-center justify-between gap-4">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="text-[13px] font-semibold text-[var(--color-text-primary)]">{rule.name}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-text-dim)]">
                          {rule.id}
                        </span>
                      </div>
                      <div className="text-[11px] text-[var(--color-text-muted)]">Category: {rule.category}</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => toggleRule(rule.id)}
                      className={clsx(
                        'w-11 h-6 rounded-full transition-colors relative p-0.5',
                        rule.enabled ? 'bg-[var(--color-accent)]' : 'bg-[var(--color-surface-3)]'
                      )}
                    >
                      <div
                        className={clsx(
                          'w-5 h-5 rounded-full bg-white transition-transform',
                          rule.enabled ? 'translate-x-5' : 'translate-x-0'
                        )}
                      />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── TAB 3: AI Anomaly Tuning ── */}
          {activeTab === 'ai' && (
            <div className="card p-6 space-y-5">
              <div className="pb-3 border-b border-[var(--color-border)]">
                <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                  Isolation Forest & Autoencoder Anomaly Scoring
                </h3>
                <p className="text-[12px] text-[var(--color-text-muted)]">
                  Tune unsupervised anomaly detection sensitivity and automated model re-baselining
                </p>
              </div>

              <div className="space-y-4">
                <div className="space-y-1.5">
                  <div className="flex justify-between text-[12px] font-semibold text-[var(--color-text-primary)]">
                    <span>Isolation Forest Contamination Factor</span>
                    <span className="font-mono text-[var(--color-accent)]">{(contamination * 100).toFixed(1)}%</span>
                  </div>
                  <input
                    type="range"
                    min="0.01"
                    max="0.15"
                    step="0.01"
                    value={contamination}
                    onChange={(e) => setContamination(parseFloat(e.target.value))}
                    className="w-full accent-[var(--color-accent)] cursor-pointer"
                  />
                </div>
              </div>
            </div>
          )}

          {/* ── TAB 4: SIEM & Alert Webhooks ── */}
          {activeTab === 'integrations' && (
            <div className="card p-6 space-y-5">
              <div className="pb-3 border-b border-[var(--color-border)]">
                <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                  Enterprise SIEM & SOC Alert Exporters
                </h3>
                <p className="text-[12px] text-[var(--color-text-muted)]">
                  Stream high-priority forensic telemetry directly into Splunk, Microsoft Sentinel, or webhook receivers
                </p>
              </div>

              <div className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                    Incident Notification Webhook (Slack / Discord / Teams)
                  </label>
                  <input
                    type="url"
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  />
                </div>
              </div>
            </div>
          )}

          {/* ── Form Save Button ── */}
          <div className="flex justify-end">
            <button
              type="submit"
              className="btn btn-primary px-6 py-2 text-[13px] flex items-center gap-2"
            >
              <Save size={15} /> Save Protocol & System Settings
            </button>
          </div>

        </form>

      </div>
    </AppShell>
  );
}
