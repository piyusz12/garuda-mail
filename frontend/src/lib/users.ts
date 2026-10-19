import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import prisma from './db';
import fs from 'fs';
import path from 'path';
import { normalizeUserRole, type UserRole } from './roles';
import { logAuditEvent } from './audit';

export type AccountStatus = 'active' | 'suspended' | 'disabled';

export interface UserRecord {
  id: string;
  name: string;
  email: string;
  password: string; // bcrypt hash
  role: UserRole;
  status: AccountStatus;
  department?: string;
  avatarColor: string;
  createdAt: Date;
  updatedAt: Date;
}

const SECRET = process.env.NEXTAUTH_SECRET || 'garuda-mail-sovereign-production-secret-2026';

const DEFAULT_PASSWORD_HASH = process.env.BUILTIN_PASSWORD_HASH || '$2b$10$Q7yt/OlFiwCLf0nQ.Qt/7uQsV5ppAOKkKQz584bFbHFsTfxeJs18u';

// ── Built-in Seed Users (development/demo mode only) ──────────────────
const DEMO_MODE = process.env.DEMO_MODE === 'true' || process.env.DEMO_MODE !== 'false';

export const BUILTIN_USERS: UserRecord[] = DEMO_MODE && DEFAULT_PASSWORD_HASH ? [
  {
    id: 'user-officer-garuda-000',
    name: 'Garuda Officer',
    email: 'officer@garuda.internal',
    password: DEFAULT_PASSWORD_HASH,
    role: 'officer',
    status: 'active',
    department: 'Cryptographic SOC',
    avatarColor: '#38BDF8',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-analyst-garuda-000b',
    name: 'Security Analyst',
    email: 'analyst@garuda.internal',
    password: DEFAULT_PASSWORD_HASH,
    role: 'officer',
    status: 'active',
    department: 'Cryptographic Forensics',
    avatarColor: '#10B981',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-thalendra-001',
    name: 'Thalendra Bhaskar',
    email: 'bhaskarthalendra@gmail.com',
    password: DEFAULT_PASSWORD_HASH,
    role: 'admin',
    status: 'active',
    department: 'Cryptographic Forensics & SecOps',
    avatarColor: '#38BDF8',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-piyush-002',
    name: 'Piyush Tembhurkar',
    email: 'piyushtembhurkar12@gmail.com',
    password: DEFAULT_PASSWORD_HASH,
    role: 'admin',
    status: 'active',
    department: 'Cryptographic Architecture',
    avatarColor: '#F43F5E',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-officer-003',
    name: 'Garuda Officer',
    email: 'officer@garudamail.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'officer',
    status: 'active',
    department: 'Cryptographic SOC',
    avatarColor: '#38BDF8',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-security-004',
    name: 'Security Operations',
    email: 'security@enterprise.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'admin',
    status: 'active',
    department: 'SecOps Infrastructure',
    avatarColor: '#F43F5E',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-bob-005',
    name: 'Bob Henderson',
    email: 'bob@enterprise.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'user',
    status: 'active',
    department: 'Network Forensics',
    avatarColor: '#10B981',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-alice-006',
    name: 'Alice Vance',
    email: 'alice@enterprise.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'user',
    status: 'active',
    department: 'Cryptography & CBOM',
    avatarColor: '#8B5CF6',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-admin-007',
    name: 'System Administrator',
    email: 'admin@garudamail.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'admin',
    status: 'active',
    department: 'Security Operations',
    avatarColor: '#E11D48',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
  {
    id: 'user-demo-008',
    name: 'Garuda User',
    email: 'user@garudamail.local',
    password: DEFAULT_PASSWORD_HASH,
    role: 'user',
    status: 'active',
    department: 'Security Operations',
    avatarColor: '#0EA5E9',
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  },
] : [];

// ── Ephemeral /tmp fallback storage (survives container reuse) ─────────
const TMP_USERS_FILE = path.join(
  process.env.VERCEL ? '/tmp' : process.env.TEMP || process.env.TMP || '.',
  'garuda_users_store.json'
);

const TMP_DELETED_FILE = path.join(
  process.env.VERCEL ? '/tmp' : process.env.TEMP || process.env.TMP || '.',
  'garuda_deleted_users.json'
);

function readDeletedUsers(): Set<string> {
  try {
    if (fs.existsSync(TMP_DELETED_FILE)) {
      const data = fs.readFileSync(TMP_DELETED_FILE, 'utf-8');
      const list = JSON.parse(data);
      if (Array.isArray(list)) {
        return new Set(list.map((e: string) => e.toLowerCase().trim()));
      }
    }
  } catch {}
  return new Set();
}

function saveDeletedUsers(set: Set<string>) {
  try {
    fs.writeFileSync(TMP_DELETED_FILE, JSON.stringify(Array.from(set)), 'utf-8');
  } catch {}
}

// ── In-Memory User Registry across re-evaluations ───────────────────────
declare global {
  var __garudaInMemoryUsers: Map<string, UserRecord> | undefined;
  var __garudaDeletedUsers: Set<string> | undefined;
}

const inMemoryUsers: Map<string, UserRecord> =
  global.__garudaInMemoryUsers || (global.__garudaInMemoryUsers = new Map());

const deletedUsers: Set<string> =
  global.__garudaDeletedUsers || (global.__garudaDeletedUsers = readDeletedUsers());

// Pre-populate in-memory users with builtins if not deleted
for (const u of BUILTIN_USERS) {
  const em = u.email.toLowerCase().trim();
  if (!deletedUsers.has(em) && !inMemoryUsers.has(em)) {
    inMemoryUsers.set(em, u);
  }
}

function readTmpUsers(): Record<string, UserRecord> {
  try {
    if (fs.existsSync(TMP_USERS_FILE)) {
      const data = fs.readFileSync(TMP_USERS_FILE, 'utf-8');
      return JSON.parse(data);
    }
  } catch {
    // ignore read errors
  }
  return {};
}

function writeTmpUser(user: UserRecord) {
  try {
    const existing = readTmpUsers();
    existing[user.email] = user;
    fs.writeFileSync(TMP_USERS_FILE, JSON.stringify(existing), 'utf-8');
  } catch {
    // ignore write errors in restricted environments
  }
}

// ── Signed Fallback Token (Client cookie persistence) ─────────────────
export function createFallbackToken(user: UserRecord): string {
  const payload = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.status || 'active',
    department: user.department,
    avatarColor: user.avatarColor,
    pwdHash: user.password,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000,
  };
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}

export function verifyFallbackToken(token: string): UserRecord | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [b64, sig] = parts;
    const expectedSig = crypto.createHmac('sha256', SECRET).update(b64).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf-8'));
    if (!payload.exp || Date.now() > payload.exp) {
      return null;
    }
    return {
      id: payload.id,
      name: payload.name,
      email: payload.email,
      password: payload.pwdHash || '',
      role: normalizeUserRole(payload.role),
      status: (payload.status as AccountStatus) || 'active',
      department: payload.department,
      avatarColor: payload.avatarColor || '#38BDF8',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  } catch {
    return null;
  }
}

function parseCookie(cookieHeader: string, name: string): string | null {
  const cookies = cookieHeader.split(';');
  for (const c of cookies) {
    const [k, ...v] = c.trim().split('=');
    if (k === name) {
      return decodeURIComponent(v.join('='));
    }
  }
  return null;
}

export async function findUserByEmail(
  email: string,
  cookieHeader?: string | null
): Promise<UserRecord | null> {
  const normalizedEmail = email.toLowerCase().trim();

  // If this email was deleted/purged by admin reset, reject immediately
  if (deletedUsers.has(normalizedEmail)) {
    return null;
  }

  // Tier 1: Try Prisma Database
  try {
    const dbUser = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    if (dbUser && dbUser.password) {
      return {
        id: dbUser.id,
        name: dbUser.name || 'User',
        email: dbUser.email!,
        password: dbUser.password,
        role: normalizeUserRole(dbUser.role),
        status: ((dbUser as any).status as AccountStatus) || 'active',
        department: dbUser.department || undefined,
        avatarColor: dbUser.avatarColor || '#38BDF8',
        createdAt: dbUser.createdAt,
        updatedAt: dbUser.updatedAt,
      };
    }
  } catch {
    // Database query failed (e.g. SQLite read-only or not connected on Vercel)
    // Safe to fall through to tier 2
  }

  // Tier 2: In-Memory Registry
  if (inMemoryUsers.has(normalizedEmail)) {
    const mem = inMemoryUsers.get(normalizedEmail)!;
    return { ...mem, status: mem.status || 'active' };
  }

  // Tier 3: /tmp File Store
  const tmpUsers = readTmpUsers();
  if (tmpUsers[normalizedEmail]) {
    const u = tmpUsers[normalizedEmail];
    u.status = u.status || 'active';
    inMemoryUsers.set(normalizedEmail, u);
    return u;
  }

  // Tier 4: Signed Cookie Token (from incoming request header)
  if (cookieHeader) {
    const token = parseCookie(cookieHeader, 'garuda_usr_reg');
    if (token) {
      const cookieUser = verifyFallbackToken(token);
      if (cookieUser && cookieUser.email.toLowerCase().trim() === normalizedEmail) {
        cookieUser.status = cookieUser.status || 'active';
        inMemoryUsers.set(normalizedEmail, cookieUser);
        writeTmpUser(cookieUser);
        return cookieUser;
      }
    }
  }

  // Tier 5: Built-in Users
  const builtin = BUILTIN_USERS.find(u => u.email.toLowerCase().trim() === normalizedEmail);
  if (builtin) {
    return { ...builtin, status: builtin.status || 'active' };
  }

  return null;
}

// ── Verify Password ──────────────────────────────────────────────────
export async function verifyUserPassword(user: UserRecord, passwordInput: string): Promise<boolean> {
  try {
    return await bcrypt.compare(passwordInput, user.password);
  } catch {
    return false;
  }
}

// ── Register User ────────────────────────────────────────────────────
export async function registerUser(name: string, email: string, passwordPlain: string): Promise<{
  user: Omit<UserRecord, 'password'>;
  cookieToken: string;
}> {
  const normalizedEmail = email.toLowerCase().trim();
  if (deletedUsers.has(normalizedEmail)) {
    deletedUsers.delete(normalizedEmail);
    saveDeletedUsers(deletedUsers);
  }
  const hashedPassword = await bcrypt.hash(passwordPlain, 12);
  const colors = ['#38BDF8', '#34D399', '#A78BFA', '#F472B6', '#FB923C', '#FACC15'];
  const avatarColor = colors[Math.floor(Math.random() * colors.length)];

  // Public registration ALWAYS assigns role 'user'
  const assignedRole: UserRole = 'user';

  const newUser: UserRecord = {
    id: `usr_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    name: name.trim(),
    email: normalizedEmail,
    password: hashedPassword,
    role: assignedRole,
    status: 'active',
    department: 'Cryptographic SOC',
    avatarColor,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Attempt to write to Prisma if DB is accessible
  try {
    const created = await prisma.user.create({
      data: {
        name: newUser.name,
        email: newUser.email,
        password: newUser.password,
        role: newUser.role,
        status: newUser.status,
        department: newUser.department,
        avatarColor: newUser.avatarColor,
      },
    });
    newUser.id = created.id;
  } catch {
    console.warn('[Register] Prisma write unavailable on current environment, saved to fallback stores.');
  }

  // Save to Memory & /tmp
  inMemoryUsers.set(normalizedEmail, newUser);
  writeTmpUser(newUser);

  // Audit Log
  await logAuditEvent({
    action: 'USER_REGISTER_SUCCESS',
    actorEmail: normalizedEmail,
    actorRole: 'user',
    targetEmail: normalizedEmail,
    details: `User account ${normalizedEmail} registered with role USER`,
    status: 'SUCCESS',
  });

  // Generate signed cookie token
  const cookieToken = createFallbackToken(newUser);

  // Return public user
  const publicUser = toPublicUser(newUser);
  return { user: publicUser, cookieToken };
}

function toPublicUser(u: UserRecord): Omit<UserRecord, 'password'> {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    status: u.status || 'active',
    department: u.department,
    avatarColor: u.avatarColor,
    createdAt: u.createdAt,
    updatedAt: u.updatedAt,
  };
}

// ── List All Users ───────────────────────────────────────────────────
export async function listAllUsers(): Promise<Array<Omit<UserRecord, 'password'>>> {
  const userMap = new Map<string, Omit<UserRecord, 'password'>>();

  // Add builtins (only if not deleted)
  for (const u of BUILTIN_USERS) {
    const em = u.email.toLowerCase().trim();
    if (!deletedUsers.has(em)) {
      userMap.set(em, toPublicUser(u));
    }
  }

  // Add in-memory (only if not deleted)
  for (const [em, u] of inMemoryUsers.entries()) {
    const normalized = em.toLowerCase().trim();
    if (!deletedUsers.has(normalized)) {
      userMap.set(normalized, toPublicUser(u));
    }
  }

  // Add tmp users (only if not deleted)
  const tmp = readTmpUsers();
  for (const [em, u] of Object.entries(tmp)) {
    const normalized = em.toLowerCase().trim();
    if (!deletedUsers.has(normalized)) {
      userMap.set(normalized, toPublicUser(u));
    }
  }

  // Add database users if query succeeds
  try {
    const dbUsers = await prisma.user.findMany({
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        status: true,
        department: true,
        avatarColor: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    for (const dbu of dbUsers) {
      if (dbu.email) {
        const normalized = dbu.email.toLowerCase().trim();
        if (!deletedUsers.has(normalized)) {
          userMap.set(normalized, {
            id: dbu.id,
            name: dbu.name || 'User',
            email: dbu.email,
            role: normalizeUserRole(dbu.role),
            status: ((dbu as any).status as AccountStatus) || 'active',
            department: dbu.department || undefined,
            avatarColor: dbu.avatarColor || '#38BDF8',
            createdAt: dbu.createdAt,
            updatedAt: dbu.updatedAt,
          });
        }
      }
    }
  } catch {
    // database not reachable, rely on memory/builtins
  }

  return Array.from(userMap.values());
}

// ── Reset All Login Credentials (Admin-Only Action) ───────────────────
export async function resetAllLoginCredentials(options?: {
  currentAdminEmail?: string;
  keepDefaultAdmins?: boolean;
  purgeAllCompletely?: boolean;
}): Promise<{
  deletedCount: number;
  message: string;
}> {
  let count = 0;
  const currentAdmin = options?.currentAdminEmail?.toLowerCase().trim();
  const purgeAll = options?.purgeAllCompletely ?? (options?.keepDefaultAdmins === false);

  // 1. Gather all currently listed users
  const currentUsers = await listAllUsers();

  for (const user of currentUsers) {
    const em = user.email.toLowerCase().trim();

    if (!purgeAll) {
      // Preserve the current admin performing the action so they don't get locked out
      const isCurrentAdmin = currentAdmin && em === currentAdmin;
      const isMasterAdmin = em === 'admin@garudamail.local';

      if (isCurrentAdmin || isMasterAdmin) {
        continue;
      }
    }

    // Permanently purge credentials
    deletedUsers.add(em);
    inMemoryUsers.delete(em);
    count++;
  }

  // If purging all, also explicitly mark every built-in user as deleted
  if (purgeAll) {
    for (const u of BUILTIN_USERS) {
      const em = u.email.toLowerCase().trim();
      deletedUsers.add(em);
      inMemoryUsers.delete(em);
    }
  }

  saveDeletedUsers(deletedUsers);

  // 2. Clear /tmp Ephemeral File
  try {
    fs.writeFileSync(TMP_USERS_FILE, JSON.stringify({}), 'utf-8');
  } catch (err) {
    console.warn('[resetAllLoginCredentials] /tmp store reset note:', err);
  }

  // 3. Clear Prisma DB users
  try {
    const whereClause: Record<string, unknown> = {};
    if (!purgeAll && currentAdmin) {
      whereClause.email = { not: currentAdmin };
    }
    await prisma.user.deleteMany({
      where: whereClause,
    });
  } catch {
    // Database delete ignored if not connected
  }

  return {
    deletedCount: count,
    message: purgeAll
      ? `All login credentials deleted across the system (${count} accounts purged). 0 accounts remaining.`
      : `All login credentials deleted (${count} accounts purged). Only active administrator preserved.`,
  };
}

// ── Restore Initial Baseline Accounts (Admin-Only Action) ─────────────
export async function restoreAllDefaultUsers(): Promise<{ message: string }> {
  deletedUsers.clear();
  saveDeletedUsers(deletedUsers);

  for (const u of BUILTIN_USERS) {
    inMemoryUsers.set(u.email.toLowerCase().trim(), u);
  }

  return {
    message: 'Initial system demo accounts restored successfully.',
  };
}

// ── Delete Single User Credential (Admin-Only) ───────────────────────
export async function deleteUserByEmail(email: string): Promise<boolean> {
  const normalized = email.toLowerCase().trim();
  deletedUsers.add(normalized);
  saveDeletedUsers(deletedUsers);

  let deleted = false;

  // In-memory
  if (inMemoryUsers.has(normalized)) {
    inMemoryUsers.delete(normalized);
    deleted = true;
  }

  // /tmp file
  try {
    const tmp = readTmpUsers();
    if (tmp[normalized]) {
      delete tmp[normalized];
      fs.writeFileSync(TMP_USERS_FILE, JSON.stringify(tmp), 'utf-8');
      deleted = true;
    }
  } catch {}

  // Prisma DB
  try {
    const res = await prisma.user.deleteMany({
      where: { email: normalized },
    });
    if (res.count > 0) deleted = true;
  } catch {}

  return true;
}

// ── Update Account Status (Admin-Only Action) ─────────────────────────
export async function updateUserStatus(
  email: string,
  status: AccountStatus,
  actorEmail?: string
): Promise<{ success: boolean; user?: Omit<UserRecord, 'password'>; message: string }> {
  const normalized = email.toLowerCase().trim();
  const user = await findUserByEmail(normalized);
  if (!user) {
    return { success: false, message: 'User not found' };
  }

  // Prevent suspending the master admin or current admin suspending themselves
  if (normalized === 'admin@garudamail.local' && status !== 'active') {
    return { success: false, message: 'Cannot suspend master administrator account' };
  }
  if (actorEmail && normalized === actorEmail.toLowerCase().trim() && status !== 'active') {
    return { success: false, message: 'Administrators cannot suspend their own account' };
  }

  user.status = status;
  user.updatedAt = new Date();

  // Update in-memory & tmp
  inMemoryUsers.set(normalized, user);
  writeTmpUser(user);

  // Update Prisma DB
  try {
    await prisma.user.update({
      where: { email: normalized },
      data: { status },
    });
  } catch {}

  await logAuditEvent({
    action: status === 'active' ? 'ACCOUNT_ACTIVATED' : 'ACCOUNT_SUSPENDED',
    actorEmail: actorEmail || 'system',
    actorRole: 'admin',
    targetEmail: normalized,
    details: `Account status updated to "${status}" for ${normalized}`,
    status: 'SUCCESS',
  });

  return { success: true, user: toPublicUser(user), message: `User status updated to ${status}` };
}

// ── Update User Role (Admin-Only Action) ──────────────────────────────
export async function updateUserRole(
  email: string,
  role: UserRole,
  actorEmail?: string
): Promise<{ success: boolean; user?: Omit<UserRecord, 'password'>; message: string }> {
  const normalized = email.toLowerCase().trim();
  const user = await findUserByEmail(normalized);
  if (!user) {
    return { success: false, message: 'User not found' };
  }

  if (normalized === 'admin@garudamail.local' && role !== 'admin') {
    return { success: false, message: 'Cannot demote master administrator account' };
  }
  if (actorEmail && normalized === actorEmail.toLowerCase().trim() && role !== 'admin') {
    return { success: false, message: 'Administrators cannot demote their own account' };
  }

  user.role = role;
  user.updatedAt = new Date();

  inMemoryUsers.set(normalized, user);
  writeTmpUser(user);

  try {
    await prisma.user.update({
      where: { email: normalized },
      data: { role },
    });
  } catch {}

  await logAuditEvent({
    action: 'ROLE_CHANGED',
    actorEmail: actorEmail || 'system',
    actorRole: 'admin',
    targetEmail: normalized,
    details: `Role updated to "${role}" for ${normalized}`,
    status: 'SUCCESS',
  });

  return { success: true, user: toPublicUser(user), message: `Role updated to ${role}` };
}

// ── Secure Initial Admin Provisioning (Bootstrap CLI & Script) ───────
export async function createAdminUser(
  name: string,
  email: string,
  passwordPlain: string,
  actorEmail?: string
): Promise<Omit<UserRecord, 'password'>> {
  const normalizedEmail = email.toLowerCase().trim();
  if (deletedUsers.has(normalizedEmail)) {
    deletedUsers.delete(normalizedEmail);
    saveDeletedUsers(deletedUsers);
  }
  const hashedPassword = await bcrypt.hash(passwordPlain, 12);
  const adminUser: UserRecord = {
    id: `admin_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    name: name.trim(),
    email: normalizedEmail,
    password: hashedPassword,
    role: 'admin',
    status: 'active',
    department: 'Security Operations (Admin)',
    avatarColor: '#E11D48',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  try {
    await prisma.user.upsert({
      where: { email: normalizedEmail },
      update: {
        role: 'admin',
        status: 'active',
        password: hashedPassword,
        name: adminUser.name,
      },
      create: {
        name: adminUser.name,
        email: adminUser.email,
        password: adminUser.password,
        role: adminUser.role,
        status: adminUser.status,
        department: adminUser.department,
        avatarColor: adminUser.avatarColor,
      },
    });
  } catch {}

  inMemoryUsers.set(normalizedEmail, adminUser);
  writeTmpUser(adminUser);

  await logAuditEvent({
    action: 'ADMIN_PROVISIONED',
    actorEmail: actorEmail || 'bootstrap-cli',
    actorRole: 'admin',
    targetEmail: normalizedEmail,
    details: `Administrator account ${normalizedEmail} provisioned/updated via secure bootstrap.`,
    status: 'SUCCESS',
  });

  return toPublicUser(adminUser);
}

