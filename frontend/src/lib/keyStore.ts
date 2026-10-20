/**
 * Garuda Mail — Cryptographic Key Registry & Trust Store (Phases 4, 5, 6)
 * Manages user public keys, SHA-256 fingerprints, trust statuses, key rotations, and revocations.
 * ZERO-KNOWLEDGE GUARANTEE: Private keys are NEVER stored or accepted by this store.
 */

import crypto from 'crypto';
import { getPublicKeyFingerprint } from './crypto';

export interface PublicKeyRecord {
  userId: string;
  userEmail: string;
  userName: string;
  encryptionPublicKey: string; // PEM format (RSA-OAEP)
  signingPublicKey: string;    // PEM format (RSA-PSS)
  fingerprint: string;         // SHA-256 hex formatted fingerprint
  signingFingerprint: string;  // SHA-256 hex formatted signing key fingerprint
  algorithm: string;           // e.g. "RSA-4096-OAEP / RSA-PSS"
  createdAt: string;
  expiresAt: string;
  isRevoked: boolean;
  revokedAt?: string;
  revocationReason?: string;
  version: number;
}

export interface PeerTrustRecord {
  ownerEmail: string;
  peerEmail: string;
  trustedFingerprint: string;
  isVerified: boolean;
  verifiedAt?: string;
  warningFlag?: boolean;
  lastSeenFingerprint?: string;
}

export interface KeyAuditEvent {
  id: string;
  userEmail: string;
  action: 'REGISTER' | 'ROTATE' | 'REVOKE' | 'VERIFY_TRUST' | 'UNTRUST' | 'SUSPECT_SUBSTITUTION';
  previousFingerprint?: string;
  newFingerprint?: string;
  timestamp: string;
  clientIp?: string;
  details: string;
}

declare global {
  var __garudaKeyRegistry: Map<string, PublicKeyRecord> | undefined;
  var __garudaTrustStore: Map<string, PeerTrustRecord> | undefined;
  var __garudaKeyAuditLog: KeyAuditEvent[] | undefined;
}

const keyRegistry: Map<string, PublicKeyRecord> =
  global.__garudaKeyRegistry || (global.__garudaKeyRegistry = new Map());

const trustStore: Map<string, PeerTrustRecord> =
  global.__garudaTrustStore || (global.__garudaTrustStore = new Map());

const auditLog: KeyAuditEvent[] =
  global.__garudaKeyAuditLog || (global.__garudaKeyAuditLog = []);

/**
 * Compute SHA-256 fingerprint for a public key PEM string
 * Uses the authoritative getPublicKeyFingerprint implementation from crypto.ts.
 */
export const calculateFingerprint = getPublicKeyFingerprint;

/**
 * Register or rotate a user's public key pair
 */
export function registerPublicKey(params: {
  userId: string;
  userEmail: string;
  userName: string;
  encryptionPublicKey: string;
  signingPublicKey?: string;
  clientIp?: string;
}): { record: PublicKeyRecord; warning?: string } {
  const email = params.userEmail.toLowerCase().trim();
  const encFp = calculateFingerprint(params.encryptionPublicKey);
  const sigKey = params.signingPublicKey || params.encryptionPublicKey;
  const sigFp = calculateFingerprint(sigKey);

  const existing = keyRegistry.get(email);
  let warning: string | undefined;

  if (existing) {
    if (existing.fingerprint !== encFp) {
      warning = `Public key rotation detected. Previous fingerprint: ${existing.fingerprint.slice(0, 14)}...`;
      auditLog.push({
        id: `AUD-${crypto.randomUUID().slice(0, 8)}`,
        userEmail: email,
        action: 'ROTATE',
        previousFingerprint: existing.fingerprint,
        newFingerprint: encFp,
        timestamp: new Date().toISOString(),
        clientIp: params.clientIp,
        details: `Public encryption key rotated from version ${existing.version} to ${existing.version + 1}`,
      });

      // Update peer trust records where this user was trusted to flag mismatch
      for (const trust of trustStore.values()) {
        if (trust.peerEmail === email && trust.trustedFingerprint !== encFp) {
          trust.warningFlag = true;
          trust.lastSeenFingerprint = encFp;
          auditLog.push({
            id: `AUD-${crypto.randomUUID().slice(0, 8)}`,
            userEmail: trust.ownerEmail,
            action: 'SUSPECT_SUBSTITUTION',
            previousFingerprint: trust.trustedFingerprint,
            newFingerprint: encFp,
            timestamp: new Date().toISOString(),
            details: `Peer key changed for ${email}! Trusted: ${trust.trustedFingerprint}, Observed: ${encFp}`,
          });
        }
      }
    }
  } else {
    auditLog.push({
      id: `AUD-${crypto.randomUUID().slice(0, 8)}`,
      userEmail: email,
      action: 'REGISTER',
      newFingerprint: encFp,
      timestamp: new Date().toISOString(),
      clientIp: params.clientIp,
      details: 'Initial public key registered',
    });
  }

  const record: PublicKeyRecord = {
    userId: params.userId,
    userEmail: email,
    userName: params.userName,
    encryptionPublicKey: params.encryptionPublicKey,
    signingPublicKey: sigKey,
    fingerprint: encFp,
    signingFingerprint: sigFp,
    algorithm: 'RSA-4096-OAEP / RSA-PSS (SHA-256)',
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
    isRevoked: false,
    version: existing ? existing.version + 1 : 1,
  };

  keyRegistry.set(email, record);
  return { record, warning };
}

/**
 * Get public key for a user
 */
export function getPublicKey(email: string): PublicKeyRecord | null {
  return keyRegistry.get(email.toLowerCase().trim()) || null;
}

/**
 * List all registered public keys
 */
export function listPublicKeys(): PublicKeyRecord[] {
  return Array.from(keyRegistry.values()).filter(k => !k.isRevoked);
}

/**
 * Mark a peer's public key as verified by the current user
 */
export function setPeerTrust(ownerEmail: string, peerEmail: string, verified: boolean): PeerTrustRecord {
  const normOwner = ownerEmail.toLowerCase().trim();
  const normPeer = peerEmail.toLowerCase().trim();
  const key = `${normOwner}->${normPeer}`;

  const peerKey = getPublicKey(normPeer);
  const currentFp = peerKey ? peerKey.fingerprint : 'UNKNOWN';

  const record: PeerTrustRecord = {
    ownerEmail: normOwner,
    peerEmail: normPeer,
    trustedFingerprint: currentFp,
    isVerified: verified,
    verifiedAt: verified ? new Date().toISOString() : undefined,
    warningFlag: false,
    lastSeenFingerprint: currentFp,
  };

  trustStore.set(key, record);

  auditLog.push({
    id: `AUD-${crypto.randomUUID().slice(0, 8)}`,
    userEmail: normOwner,
    action: verified ? 'VERIFY_TRUST' : 'UNTRUST',
    newFingerprint: currentFp,
    timestamp: new Date().toISOString(),
    details: `${verified ? 'Verified trust established for' : 'Untrusted'} peer ${normPeer}`,
  });

  return record;
}

/**
 * Check peer trust status
 */
export function getPeerTrust(ownerEmail: string, peerEmail: string): PeerTrustRecord | null {
  const normOwner = ownerEmail.toLowerCase().trim();
  const normPeer = peerEmail.toLowerCase().trim();
  const key = `${normOwner}->${normPeer}`;
  const trust = trustStore.get(key);

  if (!trust) return null;

  // Check if peer's current key differs from trusted key
  const currentPeerKey = getPublicKey(normPeer);
  if (currentPeerKey && currentPeerKey.fingerprint !== trust.trustedFingerprint) {
    return {
      ...trust,
      warningFlag: true,
      lastSeenFingerprint: currentPeerKey.fingerprint,
    };
  }

  return trust;
}

/**
 * Get Key Audit Log
 */
export function getKeyAuditLog(limit: number = 50): KeyAuditEvent[] {
  return auditLog.slice(-limit).reverse();
}

/**
 * Revoke a user's public key
 */
export function revokePublicKey(email: string, reason: string): boolean {
  const record = keyRegistry.get(email.toLowerCase().trim());
  if (!record) return false;

  record.isRevoked = true;
  record.revokedAt = new Date().toISOString();
  record.revocationReason = reason;

  auditLog.push({
    id: `AUD-${crypto.randomUUID().slice(0, 8)}`,
    userEmail: email,
    action: 'REVOKE',
    previousFingerprint: record.fingerprint,
    timestamp: new Date().toISOString(),
    details: `Key revoked: ${reason}`,
  });

  return true;
}
