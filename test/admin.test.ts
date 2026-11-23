import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { createApiApp } from '../src/api/app.js';
import { loadEnv } from '../src/config/env.js';
import type { AdminStore, AuditLogRow } from '../src/storage/adminStore.js';
import { createInbox, inboxExists } from '../src/storage/redis.js';
import type {
  AbuseReportRow,
  BlocklistRow,
  DomainRow,
  SettingRow,
  SmtpLogRow,
} from '../src/storage/repositories.js';
import { createLogger } from '../src/utils/logger.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

function createInMemoryAdminStore(): {
  store: AdminStore;
  auditLogs: AuditLogRow[];
} {
  let nextId = 1;
  const domainRows: DomainRow[] = [];
  const blocklistRows: BlocklistRow[] = [];
  const settingsMap = new Map<string, SettingRow>();
  const abuseRows: AbuseReportRow[] = [
    {
      id: 10,
      address: 'bad@temporamail.app',
      messageId: 'msg-1',
      reason: 'phishing',
      reporterIp: '203.0.113.5',
      status: 'open',
      createdAt: new Date(),
    },
  ];
  const smtpRows: SmtpLogRow[] = [
    {
      id: 1,
      time: new Date(),
      ip: '198.51.100.1',
      from: 'a@example.com',
      to: 'u@temporamail.app',
      result: 'accepted',
      reason: '',
      spamScore: 0.5,
    },
    {
      id: 2,
      time: new Date(),
      ip: '198.51.100.9',
      from: 'spam@bad.test',
      to: 'u@temporamail.app',
      result: 'rejected',
      reason: 'dnsbl:zen.spamhaus.org',
      spamScore: 0,
    },
  ];
  const auditLogs: AuditLogRow[] = [];

  const store: AdminStore = {
    async getSmtpStatsLastHour() {
      return {
        emailsLastHour: 42,
        rejectionsByReason: { 'dnsbl:zen.spamhaus.org': 7, rspamd_high_score: 3 },
      };
    },
    async listDomains() {
      return [...domainRows];
    },
    async createDomain(input) {
      const row: DomainRow = {
        id: nextId++,
        name: input.name,
        active: input.active ?? true,
        notes: input.notes ?? '',
        createdAt: new Date(),
      };
      domainRows.push(row);
      return row;
    },
    async updateDomain(id, input) {
      const idx = domainRows.findIndex((d) => d.id === id);
      if (idx === -1) {
        return null;
      }
      const existing = domainRows[idx];
      if (!existing) {
        return null;
      }
      const updated: DomainRow = {
        ...existing,
        active: input.active ?? existing.active,
        notes: input.notes ?? existing.notes,
      };
      domainRows[idx] = updated;
      return updated;
    },
    async deleteDomain(id) {
      const idx = domainRows.findIndex((d) => d.id === id);
      if (idx === -1) {
        return false;
      }
      domainRows.splice(idx, 1);
      return true;
    },
    async listBlocklist() {
      return [...blocklistRows];
    },
    async addBlocklistEntry(input) {
      const row: BlocklistRow = {
        id: nextId++,
        type: input.type,
        value: input.value.toLowerCase(),
        reason: input.reason ?? '',
        createdAt: new Date(),
      };
      blocklistRows.push(row);
      return row;
    },
    async deleteBlocklistEntry(id) {
      const idx = blocklistRows.findIndex((b) => b.id === id);
      if (idx === -1) {
        return false;
      }
      blocklistRows.splice(idx, 1);
      return true;
    },
    async listSettings() {
      return Array.from(settingsMap.values());
    },
    async upsertSetting(key, value) {
      const row: SettingRow = { key, value, updatedAt: new Date() };
      settingsMap.set(key, row);
      return row;
    },
    async listAbuseReports(status) {
      return status ? abuseRows.filter((r) => r.status === status) : [...abuseRows];
    },
    async updateAbuseReportStatus(id, status) {
      const idx = abuseRows.findIndex((r) => r.id === id);
      if (idx === -1) {
        return null;
      }
      const existing = abuseRows[idx];
      if (!existing) {
        return null;
      }
      const updated: AbuseReportRow = { ...existing, status };
      abuseRows[idx] = updated;
      return updated;
    },
    async searchSmtpLogs(filter) {
      return smtpRows.filter((row) => {
        if (filter.ip && row.ip !== filter.ip) return false;
        if (filter.result && row.result !== filter.result) return false;
        if (filter.reason && !row.reason.includes(filter.reason)) return false;
        return true;
      });
    },
    async insertAuditLog(input) {
      auditLogs.push({
        id: nextId++,
        actor: input.actor,
        action: input.action,
        target: input.target,
        details: input.details ?? {},
        createdAt: new Date(),
      });
    },
    async listAuditLogs(limit = 100) {
      return auditLogs.slice(0, limit);
    },
  };

  return { store, auditLogs };
}

describe('Step 7: Admin API (/api/v1/admin)', () => {
  const openApps: FastifyInstance[] = [];

  afterEach(async () => {
    while (openApps.length > 0) {
      const app = openApps.pop();
      if (app) {
        await app.close();
      }
    }
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  async function buildAdminApp(adminApiKey: string = 'super-secret-admin-key') {
    const redis = createMockRedis();
    const { store, auditLogs } = createInMemoryAdminStore();
    const onLiveSettingsMutated = vi.fn(async () => undefined);
    const config = loadEnv({
      NODE_ENV: 'test',
      ADMIN_API_KEY: adminApiKey,
    });
    const logger = createLogger('admin-test', 'silent', 'test');
    const app = await createApiApp({
      config,
      redis,
      logger,
      adminStore: store,
      onLiveSettingsMutated,
    });
    openApps.push(app);
    return { app, redis, auditLogs, onLiveSettingsMutated };
  }

  it('rejects requests without a valid ADMIN_API_KEY and returns 503 when unconfigured', async () => {
    const { app } = await buildAdminApp('secret-123');

    const missing = await app.inject({ method: 'GET', url: '/api/v1/admin/stats' });
    expect(missing.statusCode).toBe(401);
    expect(missing.json().error.code).toBe('ADMIN_UNAUTHORIZED');

    const wrong = await app.inject({
      method: 'GET',
      url: '/api/v1/admin/stats',
      headers: { 'x-admin-api-key': 'wrong-key' },
    });
    expect(wrong.statusCode).toBe(401);

    const { app: disabledApp } = await buildAdminApp('');
    const disabled = await disabledApp.inject({
      method: 'GET',
      url: '/api/v1/admin/stats',
      headers: { 'x-admin-api-key': 'anything' },
    });
    expect(disabled.statusCode).toBe(503);
    expect(disabled.json().error.code).toBe('ADMIN_DISABLED');
  });

  it('returns stats including live Redis active inbox count', async () => {
    const { app, redis } = await buildAdminApp();
    await createInbox(redis, { domain: 'temporamail.app', ttlSeconds: 600, ip: '127.0.0.1' });
    await createInbox(redis, { domain: 'temporamail.app', ttlSeconds: 600, ip: '127.0.0.1' });

    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/admin/stats',
      headers: { 'x-admin-api-key': 'super-secret-admin-key' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      emailsLastHour: 42,
      activeInboxes: 2,
      rejectionsByReason: { 'dnsbl:zen.spamhaus.org': 7, rspamd_high_score: 3 },
    });
  });

  it('manages domains, blocklist, settings, abuse reports, SMTP logs, and writes audit_log rows', async () => {
    const { app, redis, auditLogs, onLiveSettingsMutated } = await buildAdminApp();
    const headers = { 'x-admin-api-key': 'super-secret-admin-key' };

    // Add domain
    const addDom = await app.inject({
      method: 'POST',
      url: '/api/v1/admin/domains',
      headers,
      payload: { name: 'new.temporamail.app', notes: 'Secondary domain' },
    });
    expect(addDom.statusCode).toBe(201);
    const domId = (addDom.json() as { id: number }).id;

    // Update domain
    const patchDom = await app.inject({
      method: 'PATCH',
      url: `/api/v1/admin/domains/${domId}`,
      headers,
      payload: { active: false },
    });
    expect(patchDom.statusCode).toBe(200);
    expect((patchDom.json() as { active: boolean }).active).toBe(false);

    // Add blocklist entry
    const addBl = await app.inject({
      method: 'POST',
      url: '/api/v1/admin/blocklist',
      headers,
      payload: { type: 'domain', value: 'spam.bad', reason: 'abuse' },
    });
    expect(addBl.statusCode).toBe(201);

    // Update setting
    const putSet = await app.inject({
      method: 'PUT',
      url: '/api/v1/admin/settings/rspamd_reject_score',
      headers,
      payload: { value: 12 },
    });
    expect(putSet.statusCode).toBe(200);

    // Resolve abuse report
    const patchAbuse = await app.inject({
      method: 'PATCH',
      url: '/api/v1/admin/abuse-reports/10',
      headers,
      payload: { status: 'resolved' },
    });
    expect(patchAbuse.statusCode).toBe(200);
    expect((patchAbuse.json() as { status: string }).status).toBe('resolved');

    // Search SMTP logs
    const logs = await app.inject({
      method: 'GET',
      url: '/api/v1/admin/smtp-logs?result=rejected',
      headers,
    });
    expect(logs.statusCode).toBe(200);
    expect((logs.json() as { logs: SmtpLogRow[] }).logs).toHaveLength(1);

    // Takedown an active Redis inbox
    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });
    const delInbox = await app.inject({
      method: 'DELETE',
      url: `/api/v1/admin/inboxes/${encodeURIComponent(inbox.address)}`,
      headers,
    });
    expect(delInbox.statusCode).toBe(200);
    expect(await inboxExists(redis, inbox.address)).toBe(false);

    // Verify live settings refresh callback & audit log entries for every write
    expect(onLiveSettingsMutated).toHaveBeenCalledTimes(4);
    expect(auditLogs.map((a) => a.action)).toEqual([
      'domain.create',
      'domain.update',
      'blocklist.add',
      'settings.update',
      'abuse_report.update',
      'inbox.takedown',
    ]);
  });
});
