import fs from 'fs';
import path from 'path';
import { FALLBACK_EMAILS, type FallbackEmail } from './fallbackEmails';
import { decryptPayload } from './crypto';

// ── Ephemeral and persistent storage paths for dispatched emails ─────
const getStorageFilePath = (): string => {
  if (process.env.VERCEL) {
    return '/tmp/garuda_emails_store.json';
  }
  const primaryDataDir = path.join(process.cwd(), '.garuda_data');
  try {
    if (!fs.existsSync(primaryDataDir)) {
      fs.mkdirSync(primaryDataDir, { recursive: true });
    }
    return path.join(primaryDataDir, 'garuda_emails_store.json');
  } catch {
    const tempDir = process.env.TEMP || process.env.TMP || '.';
    return path.join(tempDir, 'garuda_emails_store.json');
  }
};

const TMP_EMAILS_FILE = getStorageFilePath();

declare global {
  var __garudaCustomEmails: FallbackEmail[] | undefined;
}

export function readCustomEmails(): FallbackEmail[] {
  let diskEmails: FallbackEmail[] = [];
  try {
    if (fs.existsSync(TMP_EMAILS_FILE)) {
      const data = fs.readFileSync(TMP_EMAILS_FILE, 'utf-8');
      const list = JSON.parse(data);
      if (Array.isArray(list)) {
        diskEmails = list;
      }
    }
  } catch (err) {
    console.warn('[EmailStore] Error reading custom emails from disk:', err);
  }

  // Also check /tmp fallback if local path differed
  if (diskEmails.length === 0 && !process.env.VERCEL && process.env.TEMP) {
    try {
      const altPath = path.join(process.env.TEMP, 'garuda_emails_store.json');
      if (fs.existsSync(altPath)) {
        const altData = fs.readFileSync(altPath, 'utf-8');
        const altList = JSON.parse(altData);
        if (Array.isArray(altList) && altList.length > 0) {
          diskEmails = altList;
        }
      }
    } catch {}
  }

  const memEmails = (global.__garudaCustomEmails && Array.isArray(global.__garudaCustomEmails))
    ? global.__garudaCustomEmails
    : [];

  // Merge disk and memory, preferring newer disk writes
  const map = new Map<string, FallbackEmail>();
  for (const item of memEmails) {
    map.set(item.id, item);
  }
  for (const item of diskEmails) {
    map.set(item.id, item);
  }

  const merged = Array.from(map.values()).sort((a, b) => {
    const timeA = new Date(a.createdAt || a.sentAt || 0).getTime();
    const timeB = new Date(b.createdAt || b.sentAt || 0).getTime();
    return timeB - timeA;
  });

  global.__garudaCustomEmails = merged;
  return merged;
}

export function saveCustomEmail(email: FallbackEmail) {
  const list = readCustomEmails();
  const existingIdx = list.findIndex(e => e.id === email.id);
  if (existingIdx >= 0) {
    list[existingIdx] = { ...list[existingIdx], ...email };
  } else {
    list.unshift(email);
  }
  global.__garudaCustomEmails = list;

  try {
    const dir = path.dirname(TMP_EMAILS_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(TMP_EMAILS_FILE, JSON.stringify(list, null, 2), 'utf-8');
  } catch (err) {
    console.warn('[EmailStore] Error saving email to disk:', err);
  }
}

export function updateCustomEmail(id: string, updates: Partial<FallbackEmail>): boolean {
  const list = readCustomEmails();
  let email = list.find(e => e.id === id);
  if (!email) {
    const fb = FALLBACK_EMAILS.find(e => e.id === id);
    if (fb) {
      email = { ...fb, ...updates };
      saveCustomEmail(email);
      return true;
    }
    return false;
  }
  Object.assign(email, updates);
  if (updates.read !== undefined) {
    for (const r of email.recipients) {
      r.read = updates.read;
    }
  }
  if (updates.starred !== undefined) {
    for (const r of email.recipients) {
      r.starred = updates.starred;
    }
  }
  if (updates.folder !== undefined) {
    for (const r of email.recipients) {
      r.folder = updates.folder;
    }
  }
  saveCustomEmail(email);
  return true;
}

export function deleteCustomEmail(id: string, permanent: boolean = false): boolean {
  let list = readCustomEmails();
  if (permanent) {
    list = list.filter(e => e.id !== id);
    global.__garudaCustomEmails = list;
    try {
      fs.writeFileSync(TMP_EMAILS_FILE, JSON.stringify(list, null, 2), 'utf-8');
    } catch {}
    return true;
  } else {
    return updateCustomEmail(id, { folder: 'trash' });
  }
}

export function findCustomEmailById(id: string): FallbackEmail | null {
  const custom = readCustomEmails().find(e => e.id === id);
  if (custom) return custom;
  const builtin = FALLBACK_EMAILS.find(e => e.id === id);
  return builtin || null;
}

export function getServerFallbackEmailsResponse(
  folder: string = 'inbox',
  search: string = '',
  userEmail?: string,
  userId?: string
) {
  const custom = readCustomEmails();
  const customIds = new Set(custom.map(c => c.id));
  const combined = [...custom, ...FALLBACK_EMAILS.filter(fb => !customIds.has(fb.id))];

  const normalizedUserEmail = userEmail?.toLowerCase().trim();

  let list = combined.filter(e => {
    const isSender = (userId && e.fromId === userId) ||
      (normalizedUserEmail && e.from?.email?.toLowerCase() === normalizedUserEmail);

    const matchedRecipient = e.recipients?.find(r =>
      (userId && r.userId === userId) ||
      (normalizedUserEmail && r.address?.toLowerCase() === normalizedUserEmail)
    );

    if (folder === 'sent') {
      if (isSender) return !e.draft && e.folder !== 'trash';
      // If user is unknown or demo environment, show all non-trash sent emails
      if (!userId && !normalizedUserEmail) return (e.folder === 'sent' || !e.draft) && e.folder !== 'trash';
      // Fallback: If marked as sent email in custom store, show in sent folder
      if (e.folder === 'sent' && !e.draft) return true;
      return false;
    } else if (folder === 'drafts' || folder === 'draft') {
      return (isSender || (!userId && !normalizedUserEmail)) && Boolean(e.draft) && e.folder !== 'trash';
    } else if (folder === 'starred') {
      return (e.starred || matchedRecipient?.starred) && e.folder !== 'trash';
    } else if (folder === 'trash') {
      return e.folder === 'trash' || matchedRecipient?.folder === 'trash';
    } else if (folder === 'archive') {
      return e.folder === 'archive' || matchedRecipient?.folder === 'archive';
    } else {
      // inbox
      if (e.folder === 'trash' || e.draft) return false;
      if (matchedRecipient) {
        return matchedRecipient.folder === 'inbox' || !matchedRecipient.folder;
      }
      // If sender addressed email to themselves
      if (isSender && normalizedUserEmail && e.recipients?.some(r => r.address?.toLowerCase() === normalizedUserEmail)) {
        return true;
      }
      // If sent by someone else, or showcase email addressed to analysts
      return !isSender && (e.folder === 'inbox' || !e.folder);
    }
  });

  if (search) {
    const s = search.toLowerCase();
    list = list.filter(e =>
      e.subject.toLowerCase().includes(s) ||
      e.body.toLowerCase().includes(s) ||
      e.from?.email?.toLowerCase().includes(s) ||
      e.from?.name?.toLowerCase().includes(s)
    );
  }

  // Count unreads for folder badges
  let inboxUnread = 0;
  let starredUnread = 0;
  let draftsCount = 0;

  for (const e of combined) {
    if (e.folder === 'trash') continue;
    const isSender = (userId && e.fromId === userId) || (normalizedUserEmail && e.from?.email?.toLowerCase() === normalizedUserEmail);
    const matchedRecipient = e.recipients?.find(r =>
      (userId && r.userId === userId) ||
      (normalizedUserEmail && r.address?.toLowerCase() === normalizedUserEmail)
    );
    if (e.draft && (isSender || (!userId && !normalizedUserEmail))) {
      draftsCount++;
    }
    const isUnread = matchedRecipient ? !matchedRecipient.read : (e.recipients?.length > 0 ? !e.recipients[0].read : false);
    if (isUnread) {
      if (matchedRecipient?.folder === 'inbox' || (!isSender && e.folder === 'inbox')) {
        inboxUnread++;
      }
      if (e.starred || matchedRecipient?.starred) {
        starredUnread++;
      }
    }
  }

  // Decrypt message bodies and compute security previews
  const decryptedList = list.map(e => {
    const dec = decryptPayload(e.body);
    const isAsymmetricV2 = typeof e.body === 'string' && e.body.includes('<!--GARUDA-E2EE-V2-->');
    return {
      ...e,
      body: dec.plaintext,
      rawCiphertext: dec.envelope ? ('ciphertext' in dec.envelope ? dec.envelope.ciphertext : null) : null,
      rawBody: e.body,
      preview: e.preview || (isAsymmetricV2 ? '[Asymmetric E2EE Encrypted Payload]' : dec.isEncrypted ? `[AES-256-GCM] ${dec.plaintext.slice(0, 120)}` : dec.plaintext.slice(0, 140)),
      isEncrypted: dec.isEncrypted || isAsymmetricV2,
      cryptoMetadata: dec.envelope || null,
    };
  });

  return {
    emails: decryptedList,
    unreadCounts: {
      inbox: inboxUnread,
      starred: starredUnread,
      sent: 0,
      drafts: draftsCount,
      trash: 0,
      archive: 0,
    },
    page: 1,
    total: decryptedList.length,
  };
}
