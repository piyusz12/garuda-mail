'use client';

import { useState, useEffect } from 'react';
import {
  Key, Shield, ShieldCheck, ShieldAlert, RefreshCw, CheckCircle2,
  AlertTriangle, Lock, Eye, EyeOff, Copy, UserCheck, History, ArrowRight
} from 'lucide-react';
import clsx from 'clsx';
import {
  generateUserKeyPair,
  getPublicKeyFingerprint,
  encryptPrivateKeyWithPassphrase,
  decryptPrivateKeyWithPassphrase,
  type UserKeyPair
} from '@/lib/crypto';
import { getClientVaultStatus, storeLocalKeyVault } from '@/lib/clientKeyVault';

interface PeerKey {
  userId: string;
  userEmail: string;
  userName: string;
  fingerprint: string;
  signingFingerprint: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
  createdAt: string;
  version: number;
}

interface PeerTrust {
  ownerEmail: string;
  peerEmail: string;
  trustedFingerprint: string;
  isVerified: boolean;
  warningFlag?: boolean;
  lastSeenFingerprint?: string;
}

interface AuditLog {
  id: string;
  userEmail: string;
  action: string;
  previousFingerprint?: string;
  newFingerprint?: string;
  timestamp: string;
  details: string;
}

export default function KeyLifecycleManager() {
  const [keyPair, setKeyPair] = useState<UserKeyPair | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [passphraseVisible, setPassphraseVisible] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error' | 'warning'; text: string } | null>(null);

  // Peer discovery state
  const [peerKeys, setPeerKeys] = useState<PeerKey[]>([]);
  const [trustMap, setTrustMap] = useState<Record<string, PeerTrust>>({});
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [selectedPeerCompare, setSelectedPeerCompare] = useState<PeerKey | null>(null);
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);

  // Load registered keys from server
  const fetchKeyData = async () => {
    try {
      const res = await fetch('/api/keys');
      if (res.ok) {
        const data = await res.json();
        if (data.keys) setPeerKeys(data.keys);
      }

      const auditRes = await fetch('/api/keys?audit=true');
      if (auditRes.ok) {
        const auditData = await auditRes.json();
        if (auditData.auditLogs) setAuditLogs(auditData.auditLogs);
      }
    } catch (e) {
      console.warn('Failed to fetch keys:', e);
    }
  };

  useEffect(() => {
    fetchKeyData();

    // Check if user has an encrypted private key bundle in localStorage
    const vault = getClientVaultStatus();
    if (vault.hasKey && vault.publicKey) {
      const encFp = vault.fingerprint;
      const sigFp = vault.signingPublicKey ? getPublicKeyFingerprint(vault.signingPublicKey) : encFp;
      setKeyPair({
        encryptionPublicKey: vault.publicKey,
        encryptionPrivateKey: '[Passphrase Locked in Local Storage]',
        signingPublicKey: vault.signingPublicKey || vault.publicKey,
        signingPrivateKey: '[Passphrase Locked in Local Storage]',
        fingerprint: encFp,
        signingFingerprint: sigFp,
      });
    }
  }, []);

  const handleGenerateAndRegister = async () => {
    if (!passphrase || passphrase.length < 8) {
      setStatusMsg({ type: 'error', text: 'Passphrase must be at least 8 characters to protect your private key.' });
      return;
    }

    setIsGenerating(true);
    setStatusMsg(null);

    try {
      // 1. Generate client-side keypairs (RSA-OAEP 2048 + RSA-PSS 2048)
      const kp = generateUserKeyPair(2048);

      // 2. Encrypt private keys with passphrase (PBKDF2 100k rounds + AES-GCM)
      const encryptedBundle = encryptPrivateKeyWithPassphrase(
        JSON.stringify({ enc: kp.encryptionPrivateKey, sig: kp.signingPrivateKey }),
        passphrase
      );

      // 3. Store encrypted bundle in client localStorage (NO PLAINTEXT PRIVATE KEYS)
      storeLocalKeyVault({
        encryptedBundle,
        encryptionPublicKey: kp.encryptionPublicKey,
        signingPublicKey: kp.signingPublicKey,
      });

      setKeyPair(kp);

      // 4. Register ONLY public keys with server
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          encryptionPublicKey: kp.encryptionPublicKey,
          signingPublicKey: kp.signingPublicKey,
        }),
      });

      const resData = await res.json();
      if (!res.ok) throw new Error(resData.error || 'Server rejected key registration');

      setStatusMsg({
        type: 'success',
        text: `Keypair generated & registered successfully! Fingerprint: ${kp.fingerprint.slice(0, 23)}...`,
      });

      fetchKeyData();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatusMsg({ type: 'error', text: `Key generation error: ${msg}` });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleToggleTrust = async (peerEmail: string, currentVerified: boolean) => {
    try {
      const res = await fetch('/api/keys/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          peerEmail,
          verified: !currentVerified,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setTrustMap(prev => ({
          ...prev,
          [peerEmail]: data.trust,
        }));
        fetchKeyData();
      }
    } catch (e) {
      console.warn('Failed to toggle trust:', e);
    }
  };

  const copyFingerprint = (textToCopy: string) => {
    navigator.clipboard.writeText(textToCopy);
    setCopiedFingerprint(true);
    setTimeout(() => setCopiedFingerprint(false), 2000);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* ── Status Banner ── */}
      {statusMsg && (
        <div
          className={clsx(
            'p-3 rounded-lg border text-[12px] flex items-center justify-between',
            statusMsg.type === 'success'
              ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
              : statusMsg.type === 'warning'
              ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
              : 'bg-red-500/15 border-red-500/30 text-red-300'
          )}
        >
          <span>{statusMsg.text}</span>
          <button
            type="button"
            onClick={() => setStatusMsg(null)}
            className="text-[11px] underline opacity-70 hover:opacity-100"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* ── Section 1: User's Cryptographic Identity ── */}
      <div className="card p-5 border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--color-border)]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Key size={20} />
            </div>
            <div>
              <h3 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <span>My Cryptographic Key Lifecycle (Phase 4, 5, 6)</span>
                {keyPair ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                    <CheckCircle2 size={10} /> Active
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                    <AlertTriangle size={10} /> Not Initialized
                  </span>
                )}
              </h3>
              <p className="text-[11px] text-[var(--color-text-muted)]">
                RSA-OAEP 2048/4096 (Encryption) + RSA-PSS (Signatures). Client-side WebCrypto execution with zero server knowledge.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={fetchKeyData}
              className="px-3 py-1.5 rounded-lg text-[11px] bg-[var(--color-surface-2)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)] flex items-center gap-1.5"
            >
              <RefreshCw size={12} />
              <span>Refresh Directory</span>
            </button>
          </div>
        </div>

        {/* Key Display or Generation Form */}
        {keyPair ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-2">
              <div className="text-[11px] font-bold text-purple-400 flex items-center justify-between">
                <span>ENCRYPTION PUBLIC KEY (RSA-OAEP)</span>
                <button
                  type="button"
                  onClick={() => copyFingerprint(keyPair.fingerprint)}
                  className="text-[10px] text-[var(--color-text-dim)] hover:text-purple-400 flex items-center gap-1"
                >
                  <Copy size={10} />
                  <span>{copiedFingerprint ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <div className="text-[10px] font-mono break-all bg-black/40 p-2 rounded border border-white/5 text-purple-300/90">
                {keyPair.fingerprint}
              </div>
              <div className="text-[10px] text-[var(--color-text-dim)] flex items-center gap-1">
                <Lock size={10} className="text-emerald-400" />
                <span>Private Key: Encrypted in local browser storage via PBKDF2</span>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] space-y-2">
              <div className="text-[11px] font-bold text-cyan-400 flex items-center justify-between">
                <span>DIGITAL SIGNING PUBLIC KEY (RSA-PSS)</span>
                <button
                  type="button"
                  onClick={() => copyFingerprint(keyPair.signingFingerprint)}
                  className="text-[10px] text-[var(--color-text-dim)] hover:text-cyan-400 flex items-center gap-1"
                >
                  <Copy size={10} />
                  <span>Copy</span>
                </button>
              </div>
              <div className="text-[10px] font-mono break-all bg-black/40 p-2 rounded border border-white/5 text-cyan-300/90">
                {keyPair.signingFingerprint}
              </div>
              <div className="text-[10px] text-[var(--color-text-dim)] flex items-center gap-1">
                <ShieldCheck size={10} className="text-cyan-400" />
                <span>Provides mathematical proof of authorship & anti-tamper verification</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-4 rounded-lg bg-purple-950/20 border border-purple-500/30 space-y-3">
            <div className="flex items-start gap-2.5">
              <Lock size={16} className="text-purple-400 mt-0.5" />
              <div>
                <h4 className="text-[12px] font-bold text-purple-300">Generate Your Personal Cryptographic Identity</h4>
                <p className="text-[11px] text-[var(--color-text-muted)]">
                  Your browser will generate an asymmetric RSA keypair. Your private key will be encrypted with your passphrase before saving.
                  The backend server will NEVER see or store your private key.
                </p>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-1">
              <div className="relative flex-1">
                <input
                  type={passphraseVisible ? 'text' : 'password'}
                  value={passphrase}
                  onChange={e => setPassphrase(e.target.value)}
                  placeholder="Enter a strong passphrase to lock private key (min 8 chars)..."
                  className="w-full bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-[12px] text-[var(--color-text-primary)] placeholder-[var(--color-text-dim)] pr-9 focus:border-purple-500/50 outline-none"
                />
                <button
                  type="button"
                  onClick={() => setPassphraseVisible(v => !v)}
                  className="absolute right-2.5 top-2.5 text-[var(--color-text-dim)] hover:text-[var(--color-text-primary)]"
                >
                  {passphraseVisible ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>

              <button
                type="button"
                onClick={handleGenerateAndRegister}
                disabled={isGenerating || !passphrase}
                className="px-4 py-2 rounded-lg text-[12px] font-semibold bg-gradient-to-r from-purple-500 to-indigo-600 text-white hover:opacity-90 disabled:opacity-50 transition-opacity flex items-center justify-center gap-2"
              >
                {isGenerating ? <RefreshCw size={14} className="animate-spin" /> : <Key size={14} />}
                <span>Generate & Register Key</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Section 2: Peer Public Key Directory & Verification (Phase 6) ── */}
      <div className="card p-5 border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">
          <div className="flex items-center gap-2.5">
            <UserCheck size={18} className="text-cyan-400" />
            <div>
              <h3 className="text-sm font-bold text-[var(--color-text-primary)]">
                Peer Public Key Directory & Trust Verification (Phase 6)
              </h3>
              <p className="text-[11px] text-[var(--color-text-muted)]">
                Discover colleague public keys, verify SHA-256 fingerprints out-of-band, and mark verified contacts.
              </p>
            </div>
          </div>

          <span className="text-[11px] font-mono text-[var(--color-text-dim)]">
            {peerKeys.length} Registered Keys
          </span>
        </div>

        {peerKeys.length === 0 ? (
          <div className="p-8 text-center text-[var(--color-text-dim)] text-[12px]">
            No peer public keys discovered yet. When other LAN devices or users log in and register their keypair, they will appear here.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-[var(--color-border)] text-[var(--color-text-dim)] uppercase text-[10px]">
                  <th className="py-2.5 px-3">Participant</th>
                  <th className="py-2.5 px-3">Key Fingerprint (SHA-256)</th>
                  <th className="py-2.5 px-3">Version</th>
                  <th className="py-2.5 px-3">Trust State</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {peerKeys.map(peer => {
                  const trust = trustMap[peer.userEmail];
                  const isVerified = trust ? trust.isVerified : false;
                  const hasWarning = trust ? trust.warningFlag : false;

                  return (
                    <tr key={peer.userEmail} className="hover:bg-[var(--color-surface-2)]/50 transition-colors">
                      <td className="py-3 px-3">
                        <div className="font-semibold text-[var(--color-text-primary)]">{peer.userName}</div>
                        <div className="text-[10px] text-[var(--color-text-dim)] font-mono">{peer.userEmail}</div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="font-mono text-[10px] text-purple-300 bg-purple-950/40 px-2 py-0.5 rounded border border-purple-500/20">
                          {peer.fingerprint.slice(0, 23)}...
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[var(--color-text-dim)]">
                        v{peer.version}
                      </td>
                      <td className="py-3 px-3">
                        {hasWarning ? (
                          <span className="badge-critical text-[10px] px-2 py-0.5 rounded font-bold flex items-center gap-1 w-fit">
                            <AlertTriangle size={10} /> KEY CHANGED!
                          </span>
                        ) : isVerified ? (
                          <span className="badge-healthy text-[10px] px-2 py-0.5 rounded font-bold flex items-center gap-1 w-fit">
                            <ShieldCheck size={10} /> Verified Peer
                          </span>
                        ) : (
                          <span className="text-[10px] text-[var(--color-text-dim)] px-2 py-0.5 rounded bg-[var(--color-surface-2)] border border-[var(--color-border)] w-fit">
                            Unverified
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => setSelectedPeerCompare(peer)}
                            className="px-2.5 py-1 rounded text-[10px] font-medium bg-[var(--color-surface-2)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)]"
                          >
                            Compare
                          </button>
                          <button
                            type="button"
                            onClick={() => handleToggleTrust(peer.userEmail, isVerified)}
                            className={clsx(
                              'px-2.5 py-1 rounded text-[10px] font-bold border transition-colors',
                              isVerified
                                ? 'bg-amber-500/20 text-amber-300 border-amber-500/30 hover:bg-amber-500/30'
                                : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/30'
                            )}
                          >
                            {isVerified ? 'Revoke Trust' : 'Mark as Trusted'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Section 3: Fingerprint Comparison Modal ── */}
      {selectedPeerCompare && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="card p-6 max-w-lg w-full bg-[var(--color-surface-1)] border border-[var(--color-border)] rounded-2xl space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[var(--color-border)]">
              <h4 className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                <ShieldCheck size={16} className="text-emerald-400" />
                <span>Out-of-Band Fingerprint Verification</span>
              </h4>
              <button
                type="button"
                onClick={() => setSelectedPeerCompare(null)}
                className="text-[var(--color-text-dim)] hover:text-[var(--color-text-primary)]"
              >
                ✕
              </button>
            </div>

            <p className="text-[11px] text-[var(--color-text-muted)]">
              To verify {selectedPeerCompare.userName} ({selectedPeerCompare.userEmail}), compare the SHA-256 fingerprint below with the fingerprint shown on their device screen (or read over a trusted phone channel).
            </p>

            <div className="p-3 bg-black/50 rounded-lg border border-purple-500/30 space-y-1">
              <div className="text-[10px] uppercase font-bold text-purple-400">Public Encryption Key Fingerprint</div>
              <div className="text-[11px] font-mono break-all text-purple-200">
                {selectedPeerCompare.fingerprint}
              </div>
            </div>

            <div className="p-3 bg-black/50 rounded-lg border border-cyan-500/30 space-y-1">
              <div className="text-[10px] uppercase font-bold text-cyan-400">Digital Signing Key Fingerprint</div>
              <div className="text-[11px] font-mono break-all text-cyan-200">
                {selectedPeerCompare.signingFingerprint}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setSelectedPeerCompare(null)}
                className="px-4 py-2 rounded-lg text-[12px] bg-[var(--color-surface-2)] text-[var(--color-text-primary)] border border-[var(--color-border)]"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Section 4: Key Lifecycle Audit Trail (Phase 6) ── */}
      <div className="card p-5 border border-[var(--color-border)] bg-[var(--color-surface-1)] space-y-3">
        <div className="flex items-center gap-2 pb-2 border-b border-[var(--color-border)]">
          <History size={16} className="text-purple-400" />
          <h4 className="text-xs font-bold text-[var(--color-text-primary)]">
            Append-Only Key Lifecycle Audit Log
          </h4>
        </div>

        {auditLogs.length === 0 ? (
          <div className="text-[11px] text-[var(--color-text-dim)]">No key lifecycle audit events recorded yet.</div>
        ) : (
          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {auditLogs.map(log => (
              <div
                key={log.id}
                className="p-2 rounded bg-[var(--color-surface-2)]/60 border border-[var(--color-border)] text-[11px] flex items-center justify-between gap-2"
              >
                <div className="flex items-center gap-2">
                  <span
                    className={clsx(
                      'px-1.5 py-0.2 rounded font-mono text-[9px] font-bold',
                      log.action === 'ROTATE'
                        ? 'bg-amber-500/20 text-amber-300'
                        : log.action === 'VERIFY_TRUST'
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : log.action === 'SUSPECT_SUBSTITUTION'
                        ? 'bg-red-500/20 text-red-300'
                        : 'bg-purple-500/20 text-purple-300'
                    )}
                  >
                    {log.action}
                  </span>
                  <span className="font-semibold text-[var(--color-text-primary)]">{log.userEmail}</span>
                  <span className="text-[var(--color-text-dim)]">{log.details}</span>
                </div>
                <span className="text-[10px] text-[var(--color-text-dim)] font-mono shrink-0">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
