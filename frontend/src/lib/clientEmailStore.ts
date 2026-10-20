'use client';

/**
 * Client-Side Resilient Email Storage for Garuda Mail
 * Ensures dispatched emails persist across serverless Lambdas (Vercel),
 * browser refreshes, and offline/standalone mode.
 */

const STORAGE_KEY = 'garuda_dispatched_emails';
const MAX_STORED_EMAILS = 100;

export interface ClientStoredEmail {
  id: string;
  subject: string;
  body: string;
  preview: string;
  fromId: string;
  from: {
    id: string;
    name: string;
    email: string;
    avatarColor?: string;
  };
  tlsVersion?: string | null;
  cipher?: string | null;
  forwardSecrecy?: boolean;
  starttls?: boolean;
  riskScore?: number;
  folder: string;
  starred: boolean;
  read?: boolean;
  draft?: boolean;
  createdAt: string;
  sentAt?: string;
  recipients: Array<{
    id: string;
    address: string;
    name: string;
    userId?: string | null;
    folder: string;
    read: boolean;
    starred: boolean;
  }>;
  attachments?: Array<{ id?: string; filename: string; size: number; mimeType: string; url?: string }>;
  isEncrypted?: boolean;
  cryptoMetadata?: any;
  rawCiphertext?: string | null;
}

export function getDispatchedEmailsFromStorage(): ClientStoredEmail[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.warn('[ClientEmailStore] Error reading from localStorage:', err);
    return [];
  }
}

export function saveDispatchedEmailToStorage(email: ClientStoredEmail): void {
  if (typeof window === 'undefined' || !email?.id) return;
  try {
    const emailToSave: ClientStoredEmail = {
      ...email,
      folder: email.folder || (email.draft ? 'drafts' : 'sent'),
      draft: Boolean(email.draft),
      createdAt: email.createdAt || new Date().toISOString(),
      sentAt: email.sentAt || (email.draft ? undefined : new Date().toISOString()),
    };

    const list = getDispatchedEmailsFromStorage();
    const existingIdx = list.findIndex(e => e.id === emailToSave.id);
    if (existingIdx >= 0) {
      list[existingIdx] = { ...list[existingIdx], ...emailToSave };
    } else {
      list.unshift(emailToSave);
    }
    const trimmed = list.slice(0, MAX_STORED_EMAILS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));

    // Mirror latest dispatched emails in cookies so Vercel Lambdas can read and sync them
    try {
      const recentSummary = trimmed.slice(0, 5).map(e => ({
        id: e.id,
        subject: e.subject,
        body: e.body,
        preview: e.preview,
        fromId: e.fromId,
        from: e.from,
        tlsVersion: e.tlsVersion || 'TLS 1.3',
        cipher: e.cipher || 'TLS_AES_256_GCM_SHA384',
        folder: e.folder || 'sent',
        draft: Boolean(e.draft),
        createdAt: e.createdAt,
        sentAt: e.sentAt,
        recipients: (e.recipients || []).map((r: any) => ({
          id: r.id || `rec-${Date.now()}`,
          address: typeof r === 'string' ? r : r.address,
          name: typeof r === 'string' ? r.split('@')[0] : r.name || r.address,
          userId: typeof r === 'string' ? null : r.userId,
          folder: typeof r === 'string' ? 'inbox' : r.folder || 'inbox',
          read: typeof r === 'string' ? false : Boolean(r.read),
          starred: typeof r === 'string' ? false : Boolean(r.starred),
        })),
        attachments: e.attachments || [],
      }));

      const encoded = encodeURIComponent(JSON.stringify(recentSummary));
      if (encoded.length < 3500) {
        document.cookie = `garuda_client_dispatched=${encoded}; path=/; max-age=604800; SameSite=Lax`;
      }
    } catch {}
  } catch (err) {
    console.warn('[ClientEmailStore] Error saving to localStorage:', err);
  }
}

export function updateDispatchedEmailInStorage(id: string, updates: Partial<ClientStoredEmail>): void {
  if (typeof window === 'undefined') return;
  try {
    const list = getDispatchedEmailsFromStorage();
    const email = list.find(e => e.id === id);
    if (email) {
      Object.assign(email, updates);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
    }
  } catch (err) {
    console.warn('[ClientEmailStore] Error updating in localStorage:', err);
  }
}

export function deleteDispatchedEmailFromStorage(id: string, permanent = false): void {
  if (typeof window === 'undefined') return;
  try {
    let list = getDispatchedEmailsFromStorage();
    if (permanent) {
      list = list.filter(e => e.id !== id);
    } else {
      const email = list.find(e => e.id === id);
      if (email) email.folder = 'trash';
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  } catch (err) {
    console.warn('[ClientEmailStore] Error deleting from localStorage:', err);
  }
}
