import crypto from 'crypto';

const SECRET_SALT = process.env.NEXTAUTH_SECRET || 'garuda-rfc8058-token-salt-secure-key';

export interface UnsubscribePayload {
  email: string;
  campaignId: string;
  timestamp: number;
}

export interface Rfc8058Headers {
  'List-Unsubscribe': string;
  'List-Unsubscribe-Post': string;
}

/**
 * Generate a cryptographically signed one-click unsubscribe token.
 */
export function generateUnsubscribeToken(email: string, campaignId: string = 'general'): string {
  const payload: UnsubscribePayload = {
    email: email.toLowerCase().trim(),
    campaignId,
    timestamp: Date.now(),
  };
  const jsonStr = JSON.stringify(payload);
  const base64Data = Buffer.from(jsonStr).toString('base64url');
  const hmac = crypto.createHmac('sha256', SECRET_SALT).update(base64Data).digest('base64url');
  return `${base64Data}.${hmac}`;
}

/**
 * Validate and parse a one-click unsubscribe token.
 */
export function verifyUnsubscribeToken(token: string): UnsubscribePayload | null {
  try {
    const [base64Data, hmac] = token.split('.');
    if (!base64Data || !hmac) return null;

    const expectedHmac = crypto.createHmac('sha256', SECRET_SALT).update(base64Data).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expectedHmac))) {
      return null;
    }

    const jsonStr = Buffer.from(base64Data, 'base64url').toString('utf-8');
    return JSON.parse(jsonStr) as UnsubscribePayload;
  } catch {
    return null;
  }
}

/**
 * Generate RFC 8058 compliant headers for an outbound email.
 * Includes both List-Unsubscribe and List-Unsubscribe-Post.
 */
export function generateRfc8058Headers(
  email: string,
  campaignId: string = 'general',
  baseUrl: string = process.env.NEXT_PUBLIC_APP_URL || 'https://garuda-mail.vercel.app'
): Rfc8058Headers {
  const token = generateUnsubscribeToken(email, campaignId);
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const unsubUrl = `${cleanBase}/api/unsubscribe/${token}`;

  return {
    'List-Unsubscribe': `<${unsubUrl}>`,
    'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
  };
}

// In-Memory Global Suppression Registry for Server Session
const globalSuppressionSet = new Set<string>();

export function isEmailSuppressed(email: string): boolean {
  return globalSuppressionSet.has(email.toLowerCase().trim());
}

export function suppressEmail(email: string): void {
  globalSuppressionSet.add(email.toLowerCase().trim());
}

export function unsuppressEmail(email: string): void {
  globalSuppressionSet.delete(email.toLowerCase().trim());
}

