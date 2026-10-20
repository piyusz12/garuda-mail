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
    const list = getDispatchedEmailsFromStorage();
    const existingIdx = list.findIndex(e => e.id === email.id);
    if (existingIdx >= 0) {
      list[existingIdx] = { ...list[existingIdx], ...email };
    } else {
      list.unshift(email);
    }
    const trimmed = list.slice(0, MAX_STORED_EMAILS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));

    // Also mirror latest dispatched email IDs in a lightweight cookie so Vercel Lambdas can read it
    try {
      const recentSummary = trimmed.slice(0, 10).map(e => ({
        id: e.id,
        subject: e.subject,
        folder: e.folder,
        fromEmail: e.from?.email,
        recipients: e.recipients?.map(r => r.address),
        createdAt: e.createdAt,
      }));
      document.cookie = `garuda_recent_dispatched=${encodeURIComponent(JSON.stringify(recentSummary))}; path=/; max-age=604800; SameSite=Lax`;
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
