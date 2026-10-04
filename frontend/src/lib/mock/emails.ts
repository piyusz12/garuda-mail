/* ─── Garuda Mail — Real Email Store ──────────────────────────────── */
import type { EmailMessage, EmailFolder } from '@/types/email';

export const mockEmails: EmailMessage[] = [];

export function getEmailsByFolder(folder: EmailFolder): EmailMessage[] {
  return [];
}

export function getEmailById(id: string): EmailMessage | undefined {
  return undefined;
}

export function searchEmails(query: string): EmailMessage[] {
  return [];
}
