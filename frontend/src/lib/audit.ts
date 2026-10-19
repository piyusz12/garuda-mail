import prisma from './db';
import fs from 'fs';
import path from 'path';

export interface AuditRecord {
  id: string;
  action: string;
  actorEmail?: string | null;
  actorRole?: string | null;
  targetEmail?: string | null;
  details?: string | null;
  status: 'SUCCESS' | 'FAILURE';
  createdAt: string;
}

const TMP_AUDIT_FILE = path.join(
  process.env.VERCEL ? '/tmp' : process.env.TEMP || process.env.TMP || '.',
  'garuda_audit_logs.json'
);

function readTmpAuditLogs(): AuditRecord[] {
  try {
    if (fs.existsSync(TMP_AUDIT_FILE)) {
      const data = fs.readFileSync(TMP_AUDIT_FILE, 'utf-8');
      const parsed = JSON.parse(data);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch {}
  return [];
}

function writeTmpAuditLogs(logs: AuditRecord[]) {
  try {
    // Keep last 1000 events in fallback file
    const trimmed = logs.slice(0, 1000);
    fs.writeFileSync(TMP_AUDIT_FILE, JSON.stringify(trimmed, null, 2), 'utf-8');
  } catch {}
}

declare global {
  var __garudaInMemoryAuditLogs: AuditRecord[] | undefined;
}

const inMemoryAuditLogs: AuditRecord[] =
  global.__garudaInMemoryAuditLogs || (global.__garudaInMemoryAuditLogs = readTmpAuditLogs());

export async function logAuditEvent(params: {
  action: string;
  actorEmail?: string | null;
  actorRole?: string | null;
  targetEmail?: string | null;
  details?: string | null;
  status?: 'SUCCESS' | 'FAILURE';
}): Promise<AuditRecord> {
  const record: AuditRecord = {
    id: `audit_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    action: params.action,
    actorEmail: params.actorEmail || 'system',
    actorRole: params.actorRole || 'system',
    targetEmail: params.targetEmail || null,
    details: params.details || null,
    status: params.status || 'SUCCESS',
    createdAt: new Date().toISOString(),
  };

  // 1. In-memory
  inMemoryAuditLogs.unshift(record);

  // 2. Persistent /tmp store
  writeTmpAuditLogs(inMemoryAuditLogs);

  // 3. Prisma Database if connected
  try {
    await prisma.auditLog.create({
      data: {
        id: record.id,
        action: record.action,
        actorEmail: record.actorEmail,
        actorRole: record.actorRole,
        targetEmail: record.targetEmail,
        details: record.details,
        status: record.status,
      },
    });
  } catch {
    // Prisma offline or schema sync in progress
  }

  return record;
}

export async function getAuditLogs(limit: number = 100): Promise<AuditRecord[]> {
  const mergedMap = new Map<string, AuditRecord>();

  // Add memory/tmp logs first
  for (const log of inMemoryAuditLogs) {
    mergedMap.set(log.id, log);
  }

  // Try DB
  try {
    const dbLogs = await prisma.auditLog.findMany({
      take: limit,
      orderBy: { createdAt: 'desc' },
    });
    for (const dbl of dbLogs) {
      mergedMap.set(dbl.id, {
        id: dbl.id,
        action: dbl.action,
        actorEmail: dbl.actorEmail,
        actorRole: dbl.actorRole,
        targetEmail: dbl.targetEmail,
        details: dbl.details,
        status: (dbl.status as 'SUCCESS' | 'FAILURE') || 'SUCCESS',
        createdAt: dbl.createdAt.toISOString(),
      });
    }
  } catch {}

  const sorted = Array.from(mergedMap.values()).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );

  return sorted.slice(0, limit);
}
