import { and, desc, eq, gte, ilike, lt, sql, type SQL } from 'drizzle-orm';
import type { BlocklistEntry, BlocklistEntryType } from '../protection/blocklist.js';
import type { Database } from './db.js';
import {
  abuseReports,
  auditLog,
  blocklist,
  domains,
  settings,
  smtpLog,
} from './schema.js';

export interface DomainRow {
  readonly id: number;
  readonly name: string;
  readonly active: boolean;
  readonly notes: string;
  readonly createdAt: Date;
}

export interface BlocklistRow {
  readonly id: number;
  readonly type: BlocklistEntryType;
  readonly value: string;
  readonly reason: string;
  readonly createdAt: Date;
}

export interface SettingRow {
  readonly key: string;
  readonly value: unknown;
  readonly updatedAt: Date;
}

export interface AbuseReportRow {
  readonly id: number;
  readonly address: string;
  readonly messageId: string | null;
  readonly reason: string;
  readonly reporterIp: string;
  readonly status: string;
  readonly createdAt: Date;
}

export interface SmtpLogInput {
  readonly ip: string;
  readonly from: string;
  readonly to: string;
  readonly result: 'accepted' | 'rejected' | 'flagged';
  readonly reason: string;
  readonly spamScore: number;
}

export interface SmtpLogRow extends SmtpLogInput {
  readonly id: number;
  readonly time: Date;
}

export interface SmtpLogFilter {
  readonly ip?: string;
  readonly from?: string;
  readonly to?: string;
  readonly result?: string;
  readonly reason?: string;
  readonly limit?: number;
}

export interface AuditLogInput {
  readonly actor: string;
  readonly action: string;
  readonly target: string;
  readonly details?: Record<string, unknown>;
}

const VALID_BLOCKLIST_TYPES = new Set<string>(['sender', 'domain', 'ip', 'keyword']);

function toBlocklistType(raw: string): BlocklistEntryType {
  return VALID_BLOCKLIST_TYPES.has(raw) ? (raw as BlocklistEntryType) : 'keyword';
}

// --- Domains ---

export async function listActiveDomains(db: Database): Promise<string[]> {
  const rows = await db
    .select({ name: domains.name })
    .from(domains)
    .where(eq(domains.active, true))
    .orderBy(domains.id);
  return rows.map((r) => r.name.toLowerCase());
}

export async function listAllDomains(db: Database): Promise<DomainRow[]> {
  return db.select().from(domains).orderBy(domains.id);
}

export async function createDomain(
  db: Database,
  input: { name: string; active?: boolean; notes?: string },
): Promise<DomainRow> {
  const [row] = await db
    .insert(domains)
    .values({
      name: input.name.trim().toLowerCase(),
      active: input.active ?? true,
      notes: input.notes ?? '',
    })
    .returning();
  if (!row) {
    throw new Error('Failed to insert domain');
  }
  return row;
}

export async function updateDomain(
  db: Database,
  id: number,
  input: { active?: boolean; notes?: string },
): Promise<DomainRow | null> {
  const updates: { active?: boolean; notes?: string } = {};
  if (input.active !== undefined) {
    updates.active = input.active;
  }
  if (input.notes !== undefined) {
    updates.notes = input.notes;
  }

  const [row] = await db.update(domains).set(updates).where(eq(domains.id, id)).returning();
  return row ?? null;
}

export async function deleteDomain(db: Database, id: number): Promise<boolean> {
  const rows = await db.delete(domains).where(eq(domains.id, id)).returning({ id: domains.id });
  return rows.length > 0;
}

// --- Blocklist ---

export async function listBlocklistRows(db: Database): Promise<BlocklistRow[]> {
  const rows = await db.select().from(blocklist).orderBy(desc(blocklist.id));
  return rows.map((r) => ({
    id: r.id,
    type: toBlocklistType(r.type),
    value: r.value,
    reason: r.reason,
    createdAt: r.createdAt,
  }));
}

export async function listBlocklistEntries(db: Database): Promise<BlocklistEntry[]> {
  const rows = await listBlocklistRows(db);
  return rows.map((r) => ({
    type: r.type,
    value: r.value,
    reason: r.reason,
  }));
}

export async function addBlocklistEntry(
  db: Database,
  input: { type: BlocklistEntryType; value: string; reason?: string },
): Promise<BlocklistRow> {
  const [row] = await db
    .insert(blocklist)
    .values({
      type: input.type,
      value: input.value.trim().toLowerCase(),
      reason: input.reason ?? '',
    })
    .returning();
  if (!row) {
    throw new Error('Failed to insert blocklist entry');
  }
  return {
    id: row.id,
    type: toBlocklistType(row.type),
    value: row.value,
    reason: row.reason,
    createdAt: row.createdAt,
  };
}

export async function deleteBlocklistEntry(db: Database, id: number): Promise<boolean> {
  const rows = await db.delete(blocklist).where(eq(blocklist.id, id)).returning({ id: blocklist.id });
  return rows.length > 0;
}

// --- Settings ---

export async function listSettings(db: Database): Promise<SettingRow[]> {
  return db.select().from(settings).orderBy(settings.key);
}

export async function upsertSetting(db: Database, key: string, value: unknown): Promise<SettingRow> {
  const [row] = await db
    .insert(settings)
    .values({
      key,
      value,
      updatedAt: new Date(),
    })
    .onConflictDoUpdate({
      target: settings.key,
      set: {
        value,
        updatedAt: new Date(),
      },
    })
    .returning();
  if (!row) {
    throw new Error(`Failed to upsert setting ${key}`);
  }
  return row;
}

// --- Abuse reports ---

export async function listAbuseReports(db: Database, status?: string): Promise<AbuseReportRow[]> {
  if (status) {
    return db
      .select()
      .from(abuseReports)
      .where(eq(abuseReports.status, status))
      .orderBy(desc(abuseReports.createdAt));
  }
  return db.select().from(abuseReports).orderBy(desc(abuseReports.createdAt));
}

export async function createAbuseReport(
  db: Database,
  input: { address: string; messageId?: string | null; reason: string; reporterIp: string },
): Promise<AbuseReportRow> {
  const [row] = await db
    .insert(abuseReports)
    .values({
      address: input.address.trim().toLowerCase(),
      messageId: input.messageId ?? null,
      reason: input.reason,
      reporterIp: input.reporterIp,
    })
    .returning();
  if (!row) {
    throw new Error('Failed to create abuse report');
  }
  return row;
}

export async function updateAbuseReportStatus(
  db: Database,
  id: number,
  status: 'open' | 'resolved' | 'dismissed',
): Promise<AbuseReportRow | null> {
  const [row] = await db
    .update(abuseReports)
    .set({ status })
    .where(eq(abuseReports.id, id))
    .returning();
  return row ?? null;
}

// --- SMTP logs ---

export async function insertSmtpLog(db: Database, input: SmtpLogInput): Promise<void> {
  await db.insert(smtpLog).values({
    ip: input.ip,
    from: input.from,
    to: input.to,
    result: input.result,
    reason: input.reason,
    spamScore: input.spamScore,
  });
}

export async function searchSmtpLogs(db: Database, filter: SmtpLogFilter): Promise<SmtpLogRow[]> {
  const conditions: SQL[] = [];
  if (filter.ip) {
    conditions.push(eq(smtpLog.ip, filter.ip));
  }
  if (filter.from) {
    conditions.push(ilike(smtpLog.from, `%${filter.from}%`));
  }
  if (filter.to) {
    conditions.push(ilike(smtpLog.to, `%${filter.to}%`));
  }
  if (filter.result) {
    conditions.push(eq(smtpLog.result, filter.result));
  }
  if (filter.reason) {
    conditions.push(ilike(smtpLog.reason, `%${filter.reason}%`));
  }

  const limit = Math.min(Math.max(filter.limit ?? 100, 1), 500);
  const query = db.select().from(smtpLog);
  const rows =
    conditions.length > 0
      ? await query.where(and(...conditions)).orderBy(desc(smtpLog.time)).limit(limit)
      : await query.orderBy(desc(smtpLog.time)).limit(limit);

  return rows.map((r) => ({
    id: r.id,
    time: r.time,
    ip: r.ip,
    from: r.from,
    to: r.to,
    result: r.result as 'accepted' | 'rejected' | 'flagged',
    reason: r.reason,
    spamScore: r.spamScore,
  }));
}

export async function purgeOldSmtpLogs(db: Database, olderThan: Date): Promise<number> {
  const deleted = await db
    .delete(smtpLog)
    .where(lt(smtpLog.time, olderThan))
    .returning({ id: smtpLog.id });
  return deleted.length;
}

export async function getSmtpStatsLastHour(db: Database): Promise<{
  emailsLastHour: number;
  rejectionsByReason: Record<string, number>;
}> {
  const since = new Date(Date.now() - 60 * 60 * 1000);

  const [acceptedRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(smtpLog)
    .where(and(gte(smtpLog.time, since), eq(smtpLog.result, 'accepted')));

  const rejectedRows = await db
    .select({
      reason: smtpLog.reason,
      count: sql<number>`count(*)::int`,
    })
    .from(smtpLog)
    .where(and(gte(smtpLog.time, since), eq(smtpLog.result, 'rejected')))
    .groupBy(smtpLog.reason);

  const rejectionsByReason: Record<string, number> = {};
  for (const row of rejectedRows) {
    const key = row.reason || 'unknown';
    rejectionsByReason[key] = row.count;
  }

  return {
    emailsLastHour: acceptedRow?.count ?? 0,
    rejectionsByReason,
  };
}

// --- Audit log ---

export async function insertAuditLog(db: Database, input: AuditLogInput): Promise<void> {
  await db.insert(auditLog).values({
    actor: input.actor,
    action: input.action,
    target: input.target,
    details: input.details ?? {},
  });
}

export async function listAuditLogs(db: Database, limit: number = 100) {
  return db
    .select()
    .from(auditLog)
    .orderBy(desc(auditLog.createdAt))
    .limit(Math.min(Math.max(limit, 1), 500));
}
