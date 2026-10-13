/* ─── Garuda Mail — Real Email Store ──────────────────────────────── */
import type { EmailMessage, EmailFolder } from '@/types/email';

export const mockEmails: EmailMessage[] = [];

export function getEmailsByFolder(_folder: EmailFolder): EmailMessage[] {
  return [];
}

export function getEmailById(_id: string): EmailMessage | undefined {
  return undefined;
}

export function searchEmails(_query: string): EmailMessage[] {
  return [];
}
