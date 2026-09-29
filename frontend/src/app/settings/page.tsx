'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Settings, Sliders, Shield, Brain, Database, Bell,
  Save, RefreshCw, CheckCircle2, AlertTriangle, Key,
  Lock, Terminal, Cpu
} from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import clsx from 'clsx';

const fadeUp = { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.3 } };

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<'engine' | 'rules' | 'ai' | 'integrations'>('engine');
  const [saveToast, setSaveToast] = useState(false);

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

  const toggleRule = (ruleId: string) => {
    setRules(prev => prev.map(r => r.id === ruleId ? { ...r, enabled: !r.enabled } : r));
  };

  return (
    <AppShell
      title="Platform Settings"
      description="Configure analysis engine parameters, forensic rule thresholds, AI models, and SIEM exporters"
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
              <CheckCircle2 size={16} /> Configuration saved and updated across forensic engines.
            </div>
            <span className="text-[11px] text-mono font-medium">RESTART NOT REQUIRED</span>
          </motion.div>
        )}

        {/* ── Settings Tabs ── */}
        <div className="flex items-center gap-2 border-b border-[var(--color-border)]">
          {[
            { id: 'engine' as const, label: 'Capture & Ingestion', icon: Cpu },
            { id: 'rules' as const, label: 'Deterministic Rules', icon: Shield },
            { id: 'ai' as const, label: 'AI Anomaly Tuning', icon: Brain },
            { id: 'integrations' as const, label: 'SIEM & Alert Webhooks', icon: Bell },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                'px-4 py-2.5 text-[13px] font-medium border-b-2 flex items-center gap-2 transition-colors',
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
                    TCP Stream Buffer Memory
                  </label>
                  <select
                    value={reassemblyBuffer}
                    onChange={(e) => setReassemblyBuffer(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  >
                    <option value="128 MB">128 MB (Lightweight)</option>
                    <option value="256 MB">256 MB (Standard Enterprise)</option>
                    <option value="1024 MB">1024 MB (High Throughput / Telecom)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                    Session Inactivity Timeout (Seconds)
                  </label>
                  <input
                    type="number"
                    value={streamTimeout}
                    onChange={(e) => setStreamTimeout(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  />
                </div>

                <div className="space-y-1.5 flex flex-col justify-center">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={retainPayloads}
                      onChange={(e) => setRetainPayloads(e.target.checked)}
                      className="rounded bg-[var(--color-surface-3)] border-[var(--color-border)] text-[var(--color-accent)] focus:ring-0"
                    />
                    <span className="text-[13px] font-medium text-[var(--color-text-primary)]">
                      Retain Court-Ready Raw Packet Payloads
                    </span>
                  </label>
                  <p className="text-[11px] text-[var(--color-text-dim)] pl-5 mt-0.5">
                    Required for generating cryptographically attested forensic evidence packages
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* ── TAB 2: Deterministic Rules ── */}
          {activeTab === 'rules' && (
            <div className="card p-6 space-y-5">
              <div className="pb-3 border-b border-[var(--color-border)] flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                    Deterministic Security Policy Rules
                  </h3>
                  <p className="text-[12px] text-[var(--color-text-muted)]">
                    Enable or disable specific RFC, NIST SP 800-52r2, and PCI-DSS 4.0 detection signatures
                  </p>
                </div>
                <div className="text-[12px] text-[var(--color-accent)] font-semibold">
                  {rules.filter(r => r.enabled).length} Active Rules
                </div>
              </div>

              <div className="space-y-3">
                {rules.map((rule) => (
                  <div
                    key={rule.id}
                    className="p-4 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] flex items-center justify-between gap-4"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-mono text-[11px] text-[var(--color-accent)] font-bold">{rule.id}</span>
                        <span className="text-[10px] text-mono uppercase px-1.5 py-0.5 bg-[var(--color-surface-3)] text-[var(--color-text-dim)] rounded">
                          {rule.category}
                        </span>
                        <span className={clsx(
                          'text-[9px] uppercase font-bold px-1.5 py-0.2 rounded',
                          rule.severity === 'critical' ? 'badge-critical' : 'badge-high'
                        )}>
                          {rule.severity}
                        </span>
                      </div>
                      <div className="text-[13px] font-medium text-[var(--color-text-primary)]">
                        {rule.name}
                      </div>
                    </div>

                    <label className="relative inline-flex items-center cursor-pointer flex-shrink-0">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={() => toggleRule(rule.id)}
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-[var(--color-surface-3)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--color-accent)]"></div>
                    </label>
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
                  AI Behavioral Anomaly Engine Tuning
                </h3>
                <p className="text-[12px] text-[var(--color-text-muted)]">
                  Fine-tune unsupervised Isolation Forest contamination rates and Autoencoder reconstruction thresholds
                </p>
              </div>

              <div className="space-y-5">
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[13px]">
                    <span className="font-semibold text-[var(--color-text-primary)]">
                      Contamination Rate (Anomaly Outlier Ratio)
                    </span>
                    <span className="text-mono font-bold text-[var(--color-accent)]">
                      {contamination * 100}%
                    </span>
                  </div>
                  <input
                    type="range"
                    min="0.01"
                    max="0.10"
                    step="0.01"
                    value={contamination}
                    onChange={(e) => setContamination(parseFloat(e.target.value))}
                    className="w-full accent-[var(--color-accent)] cursor-pointer"
                  />
                  <div className="flex justify-between text-[10px] text-[var(--color-text-dim)]">
                    <span>1% (Strict - Low False Positives)</span>
                    <span>5% (Recommended)</span>
                    <span>10% (High Sensitivity)</span>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[13px]">
                    <span className="font-semibold text-[var(--color-text-primary)]">
                      Minimum Confidence Cutoff
                    </span>
                    <span className="text-mono font-bold text-[var(--color-accent)]">
                      {confidenceCutoff}%
                    </span>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="95"
                    step="5"
                    value={confidenceCutoff}
                    onChange={(e) => setConfidenceCutoff(parseInt(e.target.value))}
                    className="w-full accent-[var(--color-accent)] cursor-pointer"
                  />
                  <div className="flex justify-between text-[10px] text-[var(--color-text-dim)]">
                    <span>50% (Permissive)</span>
                    <span>70% (Standard)</span>
                    <span>95% (High Certainty Only)</span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                    Baseline Automatic Retraining Frequency
                  </label>
                  <select
                    value={autoRetrain}
                    onChange={(e) => setAutoRetrain(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  >
                    <option value="daily">Daily (Nightly automated baseline update)</option>
                    <option value="weekly">Weekly (Standard enterprise cadence)</option>
                    <option value="monthly">Monthly</option>
                    <option value="manual">Manual Only</option>
                  </select>
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

                <div className="space-y-1.5">
                  <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                    Syslog RFC 5424 Destination (Host:Port)
                  </label>
                  <input
                    type="text"
                    value={syslogHost}
                    onChange={(e) => setSyslogHost(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:border-[var(--color-accent)]"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[12px] font-semibold text-[var(--color-text-primary)]">
                    Splunk HTTP Event Collector (HEC) Token
                  </label>
                  <input
                    type="password"
                    value={splunkHecToken}
                    onChange={(e) => setSplunkHecToken(e.target.value)}
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
              <Save size={15} /> Save Settings
            </button>
          </div>

        </form>

      </div>
    </AppShell>
  );
}
