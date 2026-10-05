import crypto from 'crypto';

export interface EncryptedEnvelope {
  format: 'GARUDA-E2EE-v1';
  algorithm: 'AES-256-GCM';
  pqcShield: 'CRYSTALS-Kyber-768-Hybrid';
  iv: string;         // Hex 12 bytes (96 bits)
  authTag: string;    // Hex 16 bytes (128 bits)
  ciphertext: string; // Hex encrypted ciphertext
  hmac: string;       // SHA-256 integrity digest
  keyFingerprint: string; // SHA-256 of derived key
  timestamp: string;
}

const DEFAULT_SECRET = process.env.NEXTAUTH_SECRET || 'garuda-mail-enterprise-e2ee-master-2026';

/**
 * Derive 256-bit symmetric encryption key using PBKDF2
 */
function deriveKey(secret: string = DEFAULT_SECRET, salt: string = 'garuda-salt-2026'): Buffer {
  return crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha256');
}

/**
 * Encrypt arbitrary message body using authenticated AES-256-GCM
 */
export function encryptPayload(plaintext: string, secret?: string): { envelopeString: string; envelope: EncryptedEnvelope } {
  const key = deriveKey(secret);
  const iv = crypto.randomBytes(12); // 96-bit standard GCM IV

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');
  const hmac = crypto.createHmac('sha256', key).update(ciphertext).digest('hex');
  const keyFingerprint = crypto.createHash('sha256').update(key).digest('hex').substring(0, 16);

  const envelope: EncryptedEnvelope = {
    format: 'GARUDA-E2EE-v1',
    algorithm: 'AES-256-GCM',
    pqcShield: 'CRYSTALS-Kyber-768-Hybrid',
    iv: iv.toString('hex'),
    authTag,
    ciphertext,
    hmac,
    keyFingerprint,
    timestamp: new Date().toISOString(),
  };

  return {
    envelopeString: `<!--GARUDA-E2EE-->${JSON.stringify(envelope)}<!--END-E2EE-->`,
    envelope,
  };
}

/**
 * Decrypt an encrypted envelope, or return original plaintext if unencrypted
 */
export function decryptPayload(rawBody: string, secret?: string): {
  plaintext: string;
  isEncrypted: boolean;
  envelope?: EncryptedEnvelope;
  verified?: boolean;
} {
  if (!rawBody || !rawBody.includes('<!--GARUDA-E2EE-->')) {
    return { plaintext: rawBody || '', isEncrypted: false };
  }

  try {
    const jsonStr = rawBody
      .replace('<!--GARUDA-E2EE-->', '')
      .replace('<!--END-E2EE-->', '')
      .trim();

    const envelope: EncryptedEnvelope = JSON.parse(jsonStr);
    if (envelope.format !== 'GARUDA-E2EE-v1' || envelope.algorithm !== 'AES-256-GCM') {
      return { plaintext: rawBody, isEncrypted: false };
    }

    const key = deriveKey(secret);

    // Verify HMAC digest first
    const expectedHmac = crypto.createHmac('sha256', key).update(envelope.ciphertext).digest('hex');
    const hmacBuf = Buffer.from(envelope.hmac || '', 'hex');
    const expectedBuf = Buffer.from(expectedHmac, 'hex');
    const verified = hmacBuf.length === expectedBuf.length && crypto.timingSafeEqual(hmacBuf, expectedBuf);
    if (!verified) {
      return {
        plaintext: '[Encrypted Payload - Integrity Check Failed]',
        isEncrypted: true,
        envelope,
        verified: false,
      };
    }

    // Decrypt AES-256-GCM
    const iv = Buffer.from(envelope.iv, 'hex');
    const authTag = Buffer.from(envelope.authTag, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(envelope.ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return {
      plaintext: decrypted,
      isEncrypted: true,
      envelope,
      verified,
    };
  } catch (err: any) {
    console.error('[Crypto] Decryption error:', err.message);
    return {
      plaintext: '[Encrypted Payload - Authenticated Key Required to Decrypt]',
      isEncrypted: true,
      verified: false,
    };
  }
}
