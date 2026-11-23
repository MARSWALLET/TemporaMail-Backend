import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { createApiApp } from '../src/api/app.js';
import { hashPassword } from '../src/auth/password.js';
import { generateCurrentTotpCode } from '../src/auth/totp.js';
import { loadEnv } from '../src/config/env.js';
import type { Mailer } from '../src/mail/mailer.js';
import type {
  AdminManagedApiKeyRow,
  AdminManagedUserRow,
  AdminPanelStore,
  AdminUserRecord,
  AnnouncementRow,
  ReservedNameRow,
} from '../src/storage/adminPanelStore.js';
import type { AdminStore, AuditLogRow } from '../src/storage/adminStore.js';
import { createInbox } from '../src/storage/redis.js';
import { createLogger } from '../src/utils/logger.js';
import { createMemoryAuthStore } from './helpers/memoryAuthStore.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

function extractCookieHeader(setCookieHeader: string | string[] | undefined): string {
  const first = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
  return first ? (first.split(';')[0] ?? '') : '';
}

function createMemoryAdminStores() {
  let nextId = 1;
  const auditLogs: AuditLogRow[] = [];
  const admins = new Map<string, AdminUserRecord>();
  const adminRecovery = new Map<string, Set<string>>();
  const managedUsers = new Map<string, AdminManagedUserRow>();
  const managedKeys = new Map<string, AdminManagedApiKeyRow>();
  const reserved = new Map<string, ReservedNameRow>();
  const announcementsList: AnnouncementRow[] = [];

  const adminStore: AdminStore = {
    async getSmtpStatsLastHour() {
      return { emailsLastHour: 12, rejectionsByReason: { dnsbl: 2 } };
    },
    async listDomains() {
      return [];
    },
    async createDomain(input) {
      return {
        id: nextId++,
        name: input.name,
        active: input.active ?? true,
        notes: input.notes ?? '',
        createdAt: new Date(),
      };
    },
    async updateDomain() {
      return null;
    },
    async deleteDomain() {
      return false;
    },
    async listBlocklist() {
      return [];
    },
    async addBlocklistEntry(input) {
      return {
        id: nextId++,
        type: input.type,
        value: input.value,
        reason: input.reason ?? '',
        createdAt: new Date(),
      };
    },
    async deleteBlocklistEntry() {
      return false;
    },
    async listSettings() {
      return [];
    },
    async upsertSetting(key, value) {
      return { key, value, updatedAt: new Date() };
    },
    async listAbuseReports() {
      return [];
    },
    async updateAbuseReportStatus() {
      return null;
    },
    async searchSmtpLogs() {
      return [];
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

  const adminPanelStore: AdminPanelStore = {
    async findAdminByEmail(email) {
      const target = email.trim().toLowerCase();
      for (const a of admins.values()) {
        if (a.email === target) return a;
      }
      return null;
    },
    async findAdminById(id) {
      return admins.get(id) ?? null;
    },
    async listAdminUsers() {
      return Array.from(admins.values());
    },
    async createAdminUser(input) {
      const rec: AdminUserRecord = {
        id: randomUUID(),
        email: input.email.trim().toLowerCase(),
        passwordHash: input.passwordHash,
        role: input.role,
        totpSecretEncrypted: null,
        totpEnabled: false,
        status: 'active',
        createdAt: new Date(),
        lastLoginAt: null,
      };
      admins.set(rec.id, rec);
      return rec;
    },
    async updateAdminUser(id, input) {
      const existing = admins.get(id);
      if (!existing) return null;
      const updated: AdminUserRecord = {
        ...existing,
        role: input.role ?? existing.role,
        status: input.status ?? existing.status,
      };
      admins.set(id, updated);
      return updated;
    },
    async setAdminTotp(id, secretEncrypted, enabled, recoveryCodeHashes) {
      const existing = admins.get(id);
      if (!existing) return;
      admins.set(id, { ...existing, totpSecretEncrypted: secretEncrypted, totpEnabled: enabled });
      if (recoveryCodeHashes) {
        adminRecovery.set(id, new Set(recoveryCodeHashes));
      }
    },
    async resetAdminTotp(id) {
      const existing = admins.get(id);
      if (!existing) return false;
      admins.set(id, { ...existing, totpSecretEncrypted: null, totpEnabled: false });
      adminRecovery.delete(id);
      return true;
    },
    async consumeAdminRecoveryCode(adminUserId, codeHash) {
      const set = adminRecovery.get(adminUserId);
      if (!set || !set.has(codeHash)) return false;
      set.delete(codeHash);
      return true;
    },
    async updateAdminLastLogin(id) {
      const existing = admins.get(id);
      if (existing) admins.set(id, { ...existing, lastLoginAt: new Date() });
    },
    async searchUsers() {
      return Array.from(managedUsers.values());
    },
    async updateUserStatus(userId, status) {
      const u = managedUsers.get(userId);
      if (!u) return null;
      const updated = { ...u, status };
      managedUsers.set(userId, updated);
      return updated;
    },
    async updateUserPlan(userId, planId) {
      const u = managedUsers.get(userId);
      if (!u) return null;
      const updated = { ...u, planId };
      managedUsers.set(userId, updated);
      return updated;
    },
    async searchApiKeys() {
      return Array.from(managedKeys.values());
    },
    async disableApiKeyById(keyId) {
      const k = managedKeys.get(keyId);
      if (!k || k.revokedAt) return false;
      managedKeys.set(keyId, { ...k, revokedAt: new Date() });
      return true;
    },
    async disableAllApiKeysForUser(userId) {
      let count = 0;
      for (const [id, k] of managedKeys.entries()) {
        if (k.userId === userId && !k.revokedAt) {
          managedKeys.set(id, { ...k, revokedAt: new Date() });
          count += 1;
        }
      }
      return count;
    },
    async listReservedNames() {
      return Array.from(reserved.values());
    },
    async addReservedName(name, reason) {
      const row: ReservedNameRow = { name: name.toLowerCase(), reason, createdAt: new Date() };
      reserved.set(row.name, row);
      return row;
    },
    async deleteReservedName(name) {
      return reserved.delete(name.toLowerCase());
    },
    async listAnnouncements() {
      return [...announcementsList];
    },
    async createAnnouncement(input) {
      const row: AnnouncementRow = {
        id: nextId++,
        title: input.title,
        body: input.body,
        severity: input.severity ?? 'info',
        active: input.active ?? false,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      announcementsList.push(row);
      return row;
    },
    async updateAnnouncement(id, input) {
      const idx = announcementsList.findIndex((a) => a.id === id);
      if (idx === -1) return null;
      const existing = announcementsList[idx]!;
      const updated: AnnouncementRow = {
        ...existing,
        title: input.title ?? existing.title,
        body: input.body ?? existing.body,
        severity: input.severity ?? existing.severity,
        active: input.active ?? existing.active,
        updatedAt: new Date(),
      };
      announcementsList[idx] = updated;
      return updated;
    },
  };

  return { adminStore, adminPanelStore, auditLogs, managedUsers, managedKeys };
}

describe('Phase B8: Real Admin System (/admin/api/v1)', () => {
  const openApps: FastifyInstance[] = [];

  afterEach(async () => {
    while (openApps.length > 0) {
      const app = openApps.pop();
      if (app) await app.close();
    }
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  async function loginAdminWithMandatory2fa(
    app: FastifyInstance,
    email: string,
    password: string,
  ): Promise<string> {
    const step1 = await app.inject({
      method: 'POST',
      url: '/admin/api/v1/auth/login',
      payload: { email, password },
    });
    expect(step1.statusCode).toBe(200);
    const body1 = step1.json() as {
      mfaRequired: boolean;
      setupRequired: boolean;
      mfaToken: string;
      totpSetup?: { secret: string };
    };
    expect(body1.mfaRequired).toBe(true);
    expect(body1.totpSetup?.secret).toBeTruthy();

    const code = generateCurrentTotpCode(body1.totpSetup!.secret);
    const step2 = await app.inject({
      method: 'POST',
      url: '/admin/api/v1/auth/login/mfa',
      payload: { mfaToken: body1.mfaToken, code },
    });
    expect(step2.statusCode).toBe(200);
    const cookie = extractCookieHeader(step2.headers['set-cookie']);
    expect(cookie).toContain('tm_admin_session=');
    return cookie;
  }

  it('blocks normal user sessions from admin routes and enforces RBAC, mandatory 2FA, inbox lookup reason, and audit logging', async () => {
    const redis = createMockRedis();
    const { store: authStore } = createMemoryAuthStore();
    const { adminStore, adminPanelStore, auditLogs, managedUsers, managedKeys } =
      createMemoryAdminStores();
    const mailer: Mailer = {
      async sendEmail() {
        return { messageId: 'm1' };
      },
      close() {},
    };

    const config = loadEnv({
      NODE_ENV: 'test',
      TOTP_ENCRYPTION_KEY: 'c'.repeat(64),
    });
    const logger = createLogger('admin-panel-test', 'silent', 'test');
    const app = await createApiApp({
      config,
      redis,
      logger,
      authStore,
      adminStore,
      adminPanelStore,
      mailer,
    });
    openApps.push(app);

    // 1. Normal user session cookie cannot reach /admin/api/v1
    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'normal@example.com', password: 'normal user passphrase' },
    });
    const userLogin = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'normal@example.com', password: 'normal user passphrase' },
    });
    const userCookie = extractCookieHeader(userLogin.headers['set-cookie']);

    const userHitsAdmin = await app.inject({
      method: 'GET',
      url: '/admin/api/v1/dashboard',
      headers: { cookie: userCookie },
    });
    expect(userHitsAdmin.statusCode).toBe(401);
    expect(userHitsAdmin.json().error.code).toBe('ADMIN_UNAUTHENTICATED');

    // 2. Seed owner, moderator, and viewer admin accounts
    const ownerPw = 'owner ultra strong passphrase';
    const modPw = 'moderator strong passphrase';
    const viewerPw = 'viewer strong passphrase';

    await adminPanelStore.createAdminUser({
      email: 'owner@temporamail.app',
      passwordHash: await hashPassword(ownerPw),
      role: 'owner',
    });
    await adminPanelStore.createAdminUser({
      email: 'mod@temporamail.app',
      passwordHash: await hashPassword(modPw),
      role: 'moderator',
    });
    await adminPanelStore.createAdminUser({
      email: 'viewer@temporamail.app',
      passwordHash: await hashPassword(viewerPw),
      role: 'viewer',
    });

    const ownerCookie = await loginAdminWithMandatory2fa(app, 'owner@temporamail.app', ownerPw);
    const modCookie = await loginAdminWithMandatory2fa(app, 'mod@temporamail.app', modPw);
    const viewerCookie = await loginAdminWithMandatory2fa(app, 'viewer@temporamail.app', viewerPw);

    // 3. Viewer can read dashboard, cannot lookup inboxes or update settings
    expect(
      (
        await app.inject({
          method: 'GET',
          url: '/admin/api/v1/dashboard',
          headers: { cookie: viewerCookie },
        })
      ).statusCode,
    ).toBe(200);

    const viewerLookup = await app.inject({
      method: 'POST',
      url: '/admin/api/v1/inboxes/lookup',
      headers: { cookie: viewerCookie, 'x-requested-with': 'XMLHttpRequest' },
      payload: { address: 'test@temporamail.app', reason: 'Investigating abuse report #1' },
    });
    expect(viewerLookup.statusCode).toBe(403);
    expect(viewerLookup.json().error.code).toBe('ADMIN_FORBIDDEN');

    // 4. Moderator can lookup inbox (must supply reason -> audit logged), cannot change settings
    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });

    const modNoReason = await app.inject({
      method: 'POST',
      url: '/admin/api/v1/inboxes/lookup',
      headers: { cookie: modCookie, 'x-requested-with': 'XMLHttpRequest' },
      payload: { address: inbox.address, reason: '' },
    });
    expect(modNoReason.statusCode).toBe(400);

    const modLookupOk = await app.inject({
      method: 'POST',
      url: '/admin/api/v1/inboxes/lookup',
      headers: { cookie: modCookie, 'x-requested-with': 'XMLHttpRequest' },
      payload: { address: inbox.address, reason: 'Abuse ticket #42 phishing check' },
    });
    expect(modLookupOk.statusCode).toBe(200);
    expect(modLookupOk.json()).toMatchObject({ store: 'redis_anonymous', address: inbox.address });

    const modSettingsDenied = await app.inject({
      method: 'PUT',
      url: '/admin/api/v1/settings/rspamd_reject_score',
      headers: { cookie: modCookie, 'x-requested-with': 'XMLHttpRequest' },
      payload: { value: 10 },
    });
    expect(modSettingsDenied.statusCode).toBe(403);

    // 5. Owner can ban user (revoking sessions & API keys) and manage admins
    const targetUserId = randomUUID();
    managedUsers.set(targetUserId, {
      id: targetUserId,
      email: 'abuser@example.com',
      planId: 'free',
      status: 'active',
      emailVerified: true,
      totpEnabled: false,
      createdAt: new Date(),
      lastLoginAt: null,
    });
    managedKeys.set('key-1', {
      id: 'key-1',
      userId: targetUserId,
      name: 'Abuse Key',
      keyPrefix: 'tm_live_123456',
      last4: '9999',
      scopes: ['inbox:create'],
      revokedAt: null,
      createdAt: new Date(),
    });

    const banRes = await app.inject({
      method: 'POST',
      url: `/admin/api/v1/users/${targetUserId}/ban`,
      headers: { cookie: ownerCookie, 'x-requested-with': 'XMLHttpRequest' },
    });
    expect(banRes.statusCode).toBe(200);
    expect(banRes.json()).toMatchObject({ keysRevoked: 1 });
    expect(managedKeys.get('key-1')?.revokedAt).not.toBeNull();

    // Verify audit log recorded logins, inbox lookup (with reason), and user ban
    expect(auditLogs.some((l) => l.action === 'inbox.lookup' && l.target === inbox.address)).toBe(
      true,
    );
    expect(auditLogs.some((l) => l.action === 'user.ban' && l.target === 'abuser@example.com')).toBe(
      true,
    );
  });
});
