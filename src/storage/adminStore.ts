import type { BlocklistEntryType } from '../protection/blocklist.js';
import type { Database } from './db.js';
import {
  addBlocklistEntry,
  createDomain,
  deleteBlocklistEntry,
  deleteDomain,
  getSmtpStatsLastHour,
  insertAuditLog,
  listAbuseReports,
  listAllDomains,
  listAuditLogs,
  listBlocklistRows,
  listSettings,
  searchSmtpLogs,
  updateAbuseReportStatus,
  updateDomain,
  upsertSetting,
  type AbuseReportRow,
  type AuditLogInput,
  type BlocklistRow,
  type DomainRow,
  type SettingRow,
  type SmtpLogFilter,
  type SmtpLogRow,
} from './repositories.js';

export interface AuditLogRow {
  readonly id: number;
  readonly actor: string;
  readonly action: string;
  readonly target: string;
  readonly details: unknown;
  readonly createdAt: Date;
}

export interface AdminStore {
  getSmtpStatsLastHour(): Promise<{
    emailsLastHour: number;
    rejectionsByReason: Record<string, number>;
  }>;
  listDomains(): Promise<DomainRow[]>;
  createDomain(input: { name: string; active?: boolean; notes?: string }): Promise<DomainRow>;
  updateDomain(id: number, input: { active?: boolean; notes?: string }): Promise<DomainRow | null>;
  deleteDomain(id: number): Promise<boolean>;
  listBlocklist(): Promise<BlocklistRow[]>;
  addBlocklistEntry(input: {
    type: BlocklistEntryType;
    value: string;
    reason?: string;
  }): Promise<BlocklistRow>;
  deleteBlocklistEntry(id: number): Promise<boolean>;
  listSettings(): Promise<SettingRow[]>;
  upsertSetting(key: string, value: unknown): Promise<SettingRow>;
  listAbuseReports(status?: string): Promise<AbuseReportRow[]>;
  updateAbuseReportStatus(
    id: number,
    status: 'open' | 'resolved' | 'dismissed',
  ): Promise<AbuseReportRow | null>;
  searchSmtpLogs(filter: SmtpLogFilter): Promise<SmtpLogRow[]>;
  insertAuditLog(input: AuditLogInput): Promise<void>;
  listAuditLogs(limit?: number): Promise<AuditLogRow[]>;
}

export function createDbAdminStore(db: Database): AdminStore {
  return {
    getSmtpStatsLastHour: () => getSmtpStatsLastHour(db),
    listDomains: () => listAllDomains(db),
    createDomain: (input) => createDomain(db, input),
    updateDomain: (id, input) => updateDomain(db, id, input),
    deleteDomain: (id) => deleteDomain(db, id),
    listBlocklist: () => listBlocklistRows(db),
    addBlocklistEntry: (input) => addBlocklistEntry(db, input),
    deleteBlocklistEntry: (id) => deleteBlocklistEntry(db, id),
    listSettings: () => listSettings(db),
    upsertSetting: (key, value) => upsertSetting(db, key, value),
    listAbuseReports: (status) => listAbuseReports(db, status),
    updateAbuseReportStatus: (id, status) => updateAbuseReportStatus(db, id, status),
    searchSmtpLogs: (filter) => searchSmtpLogs(db, filter),
    insertAuditLog: (input) => insertAuditLog(db, input),
    listAuditLogs: (limit) => listAuditLogs(db, limit),
  };
}
