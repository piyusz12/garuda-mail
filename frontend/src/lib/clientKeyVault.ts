/**
 * Garuda Mail — Client Key Vault Manager (Browser Storage Single Source of Truth)
 * Standardizes read/write of client encrypted keys, public keys, and SHA-256 fingerprints in localStorage.
 * ZERO-KNOWLEDGE GUARANTEE: Never transmits private keys or passphrases to server.
 */

import { getPublicKeyFingerprint } from './crypto';

export interface ClientVaultStatus {
  hasKey: boolean;
  fingerprint: string;
  algorithm: string;
  publicKey: string | null;
  signingPublicKey: string | null;
  hasEncryptedBundle: boolean;
}

export function getClientVaultStatus(): ClientVaultStatus {
  if (typeof window === 'undefined') {
    return {
      hasKey: false,
      fingerprint: 'Server-side rendering (vault unavailable)',
      algorithm: 'RSA-OAEP-2048 / RSA-PSS-2048',
      publicKey: null,
      signingPublicKey: null,
      hasEncryptedBundle: false,
    };
  }

  try {
    const rawBundle = localStorage.getItem('garuda_key_bundle');
    const savedPub = localStorage.getItem('garuda_pub_key');
    const savedSigPub = localStorage.getItem('garuda_sig_pub_key');

    let fingerprint = '';
    let hasKey = false;
    let algorithm = 'RSA-OAEP-2048 / RSA-PSS-2048';

    if (savedPub) {
      fingerprint = getPublicKeyFingerprint(savedPub);
      hasKey = true;
    } else if (rawBundle) {
      try {
        const parsed = JSON.parse(rawBundle);
        if (parsed.fingerprint) {
          fingerprint = parsed.fingerprint;
          hasKey = true;
        }
        if (parsed.algorithm) {
          algorithm = parsed.algorithm;
        }
      } catch {}
    }

    if (!hasKey) {
      fingerprint = 'No local vault initialized on this browser device.';
    }

    return {
      hasKey,
      fingerprint,
      algorithm,
      publicKey: savedPub,
      signingPublicKey: savedSigPub,
      hasEncryptedBundle: Boolean(rawBundle),
    };
  } catch {
    return {
      hasKey: false,
      fingerprint: 'Failed to access browser local storage.',
      algorithm: 'RSA-OAEP-2048 / RSA-PSS-2048',
      publicKey: null,
      signingPublicKey: null,
      hasEncryptedBundle: false,
    };
  }
}

export function storeLocalKeyVault(params: {
  encryptedBundle: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
}): void {
  if (typeof window === 'undefined') return;
  localStorage.setItem('garuda_key_bundle', params.encryptedBundle);
  localStorage.setItem('garuda_pub_key', params.encryptionPublicKey);
  localStorage.setItem('garuda_sig_pub_key', params.signingPublicKey);
}

export function clearLocalKeyVault(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem('garuda_key_bundle');
  localStorage.removeItem('garuda_pub_key');
  localStorage.removeItem('garuda_sig_pub_key');
}
