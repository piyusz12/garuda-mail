/* ─── Garuda Mail — Email Experience Types ─────────────────────── */
/* These types power the analyst-facing email interface that wraps  */
/* around the forensic session data                                */

export type EmailFolder = 'inbox' | 'sent' | 'drafts' | 'starred' | 'archive' | 'trash';

export type SecurityLevel = 'secure' | 'warning' | 'critical' | 'unknown';

export interface EmailParticipant {
  name: string;
  email: string;
  domain: string;
}

export interface EmailSecuritySummary {
  level: SecurityLevel;
  tlsVersion: string | null;
  cipher: string | null;
  forwardSecrecy: boolean | null;
  starttls: boolean | null;
  certificateStatus: string | null;
  riskScore: number | null;
  anomalyScore: number | null;
  findingsCount: number;
  /** Linked forensic session ID */
  sessionId: string | null;
}

export interface EmailAttachment {
  name: string;
  size: number;
  type: string;
}

export interface EmailMessage {
  id: string;
  folder: EmailFolder;
  from: EmailParticipant;
  to: EmailParticipant[];
  cc?: EmailParticipant[];
  subject: string;
  preview: string;
  body: string;
  timestamp: string;
  read: boolean;
  starred: boolean;
  attachments: EmailAttachment[];
  security: EmailSecuritySummary;
  /** Thread ID for grouping related emails */
  threadId: string;
  /** Labels for categorization */
  labels: string[];
}
