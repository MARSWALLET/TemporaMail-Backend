import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { createApiApp } from '../src/api/app.js';
import { loadEnv } from '../src/config/env.js';
import type { Mailer } from '../src/mail/mailer.js';
import type { ApiKeyRecord, ApiKeyStore } from '../src/storage/apiKeyStore.js';
import type { AuthStore } from '../src/storage/authStore.js';
import { DEFAULT_PLAN_LIMITS, type PlanLimits } from '../src/storage/plans.js';
import { createLogger } from '../src/utils/logger.js';
import { createMemoryAuthStore } from './helpers/memoryAuthStore.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

function createMemoryApiKeyStore(authStore: AuthStore) {
  const keysById = new Map<string, ApiKeyRecord & { keyHash: string }>();
  const keyIdByHash = new Map<string, string>();
  const usageByKey = new Map<string, Map<string, number>>();

  const store: ApiKeyStore = {
    async listUserApiKeys(userId) {
      return Array.from(keysById.values())
        .filter((k) => k.userId === userId)
        .map(({ keyHash: _h, ...rest }) => rest);
    },
    async countActiveUserApiKeys(userId) {
      return Array.from(keysById.values()).filter(
        (k) => k.userId === userId && k.revokedAt === null,
      ).length;
    },
    async createApiKey(input) {
      const record: ApiKeyRecord & { keyHash: string } = {
        id: randomUUID(),
        userId: input.userId,
        name: input.name,
        keyPrefix: input.keyPrefix,
        last4: input.last4,
        keyHash: input.keyHash,
        scopes: [...input.scopes],
        createdAt: new Date(),
        lastUsedAt: null,
        lastIp: null,
        revokedAt: null,
      };
      keysById.set(record.id, record);
      keyIdByHash.set(input.keyHash, record.id);
      const { keyHash: _h, ...pub } = record;
      return pub;
    },
    async updateApiKey(userId, keyId, input) {
      const existing = keysById.get(keyId);
      if (!existing || existing.userId !== userId || existing.revokedAt !== null) {
        return null;
      }
      const updated = {
        ...existing,
        name: input.name ?? existing.name,
        scopes: input.scopes ? [...input.scopes] : existing.scopes,
      };
      keysById.set(keyId, updated);
      const { keyHash: _h, ...pub } = updated;
      return pub;
    },
    async revokeApiKey(userId, keyId) {
      const existing = keysById.get(keyId);
      if (!existing || existing.userId !== userId || existing.revokedAt !== null) {
        return false;
      }
      keysById.set(keyId, { ...existing, revokedAt: new Date() });
      return true;
    },
    async revokeAllUserApiKeys(userId) {
      let count = 0;
      for (const [id, k] of keysById.entries()) {
        if (k.userId === userId && k.revokedAt === null) {
          keysById.set(id, { ...k, revokedAt: new Date() });
          count += 1;
        }
      }
      return count;
    },
    async findApiKeyByHash(keyHash) {
      const id = keyIdByHash.get(keyHash);
      if (!id) return null;
      const rec = keysById.get(id);
      if (!rec) return null;
      const user = await authStore.findUserById(rec.userId);
      if (!user) return null;
      const { keyHash: _h, ...pub } = rec;
      return {
        key: pub,
        userPlanId: user.planId,
        userStatus: user.status,
      };
    },
    async recordApiKeyUsage(keyId, ip, day) {
      const rec = keysById.get(keyId);
      if (rec) {
        keysById.set(keyId, { ...rec, lastUsedAt: new Date(), lastIp: ip });
      }
      let map = usageByKey.get(keyId);
      if (!map) {
        map = new Map<string, number>();
        usageByKey.set(keyId, map);
      }
      map.set(day, (map.get(day) ?? 0) + 1);
    },
    async getApiKeyUsage(userId, keyId) {
      const rec = keysById.get(keyId);
      if (!rec || rec.userId !== userId) return null;
      const map = usageByKey.get(keyId);
      if (!map) return [];
      return Array.from(map.entries()).map(([day, count]) => ({ day, count }));
    },
  };

  return { store, keysById };
}

function extractCookieHeader(setCookieHeader: string | string[] | undefined): string {
  const first = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
  return first ? (first.split(';')[0] ?? '') : '';
}

describe('Phase B7: API Keys (tm_live_, scopes, rate limits, immediate revocation)', () => {
  const openApps: FastifyInstance[] = [];

  afterEach(async () => {
    while (openApps.length > 0) {
      const app = openApps.pop();
      if (app) await app.close();
    }
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  async function buildApiKeyApp(options: { nodeEnv?: 'test' | 'production'; dailyLimit?: number } = {}) {
    const redis = createMockRedis();
    const { store: baseAuthStore } = createMemoryAuthStore();
    const authStore: AuthStore = {
      ...baseAuthStore,
      async loadPlansMap() {
        return new Map<string, PlanLimits>([
          ['anonymous', DEFAULT_PLAN_LIMITS.anonymous],
          [
            'free',
            {
              ...DEFAULT_PLAN_LIMITS.free,
              ...(options.dailyLimit !== undefined ? { apiRequestsPerDay: options.dailyLimit } : {}),
            },
          ],
          ['premium', DEFAULT_PLAN_LIMITS.premium],
        ]);
      },
    };
    const { store: apiKeyStore, keysById } = createMemoryApiKeyStore(authStore);
    const sentTemplates: string[] = [];
    const mailer: Mailer = {
      async sendEmail(_to, template) {
        sentTemplates.push(template);
        return { messageId: `m-${sentTemplates.length}` };
      },
      close() {},
    };

    const config = loadEnv({
      NODE_ENV: options.nodeEnv ?? 'test',
      ALLOWED_DOMAINS: 'temporamail.app',
      TOTP_ENCRYPTION_KEY: 'a'.repeat(64),
    });
    const logger = createLogger('apikey-test', 'silent', 'test');
    const app = await createApiApp({
      config,
      redis,
      logger,
      authStore,
      apiKeyStore,
      mailer,
    });
    openApps.push(app);
    return { app, authStore, apiKeyStore, keysById, sentTemplates };
  }

  it('requires verified email, returns full tm_live_ key once, stores hash only, enforces scopes and immediate revocation', async () => {
    const { app, authStore, keysById, sentTemplates } = await buildApiKeyApp();

    // Signup + login unverified user
    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'dev@example.com', password: 'developer strong passphrase' },
    });
    const login = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'dev@example.com', password: 'developer strong passphrase' },
    });
    const cookie = extractCookieHeader(login.headers['set-cookie']);
    const authHeaders = { cookie, 'x-requested-with': 'XMLHttpRequest' };

    // Unverified user cannot create API key
    const unverifiedRes = await app.inject({
      method: 'POST',
      url: '/api/v1/account/api-keys',
      headers: authHeaders,
      payload: { name: 'CI Key' },
    });
    expect(unverifiedRes.statusCode).toBe(403);
    expect(unverifiedRes.json().error.code).toBe('EMAIL_VERIFICATION_REQUIRED');

    // Verify user
    const user = await authStore.findUserByEmail('dev@example.com');
    await authStore.markEmailVerified(user!.id);

    // Create restricted-scope key (read-only)
    const createReadKey = await app.inject({
      method: 'POST',
      url: '/api/v1/account/api-keys',
      headers: authHeaders,
      payload: { name: 'Read Only', scopes: ['inbox:read'] },
    });
    expect(createReadKey.statusCode).toBe(201);
    const readKeyBody = createReadKey.json() as {
      apiKey: { id: string; keyPrefix: string; last4: string };
      key: string;
    };
    expect(readKeyBody.key.startsWith('tm_live_')).toBe(true);
    expect(sentTemplates).toContain('api_key_created');

    // Stored record has hash only (not plaintext key)
    const storedRec = keysById.get(readKeyBody.apiKey.id);
    expect(storedRec?.keyHash).not.toBe(readKeyBody.key);
    expect(storedRec?.keyHash).toMatch(/^[0-9a-f]{64}$/);

    // List endpoint never exposes full key or keyHash
    const listRes = await app.inject({
      method: 'GET',
      url: '/api/v1/account/api-keys',
      headers: { cookie },
    });
    expect(listRes.statusCode).toBe(200);
    expect(JSON.stringify(listRes.json())).not.toContain(readKeyBody.key);

    // Scope enforcement: read-only key cannot POST /inbox
    const forbiddenCreate = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      headers: { Authorization: `Bearer ${readKeyBody.key}` },
      payload: {},
    });
    expect(forbiddenCreate.statusCode).toBe(403);
    expect(forbiddenCreate.json().error.code).toBe('INSUFFICIENT_SCOPE');

    // Create full-scope key (#2 = free plan max)
    const createFullKey = await app.inject({
      method: 'POST',
      url: '/api/v1/account/api-keys',
      headers: authHeaders,
      payload: { name: 'Full Key' },
    });
    expect(createFullKey.statusCode).toBe(201);
    const fullKeyBody = createFullKey.json() as { apiKey: { id: string }; key: string };

    // 3rd key exceeds free plan limit (2)
    const thirdKey = await app.inject({
      method: 'POST',
      url: '/api/v1/account/api-keys',
      headers: authHeaders,
      payload: { name: 'Extra Key' },
    });
    expect(thirdKey.statusCode).toBe(403);
    expect(thirdKey.json().error.code).toBe('PLAN_LIMIT_EXCEEDED');

    // Full key can create inbox and list messages
    const createdInbox = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      headers: { Authorization: `Bearer ${fullKeyBody.key}` },
      payload: { ttlMinutes: 120 }, // > 60 min anonymous cap, allowed by free plan 24h!
    });
    expect(createdInbox.statusCode).toBe(201);

    // Revoke key -> rejected immediately on next request
    const revokeRes = await app.inject({
      method: 'DELETE',
      url: `/api/v1/account/api-keys/${fullKeyBody.apiKey.id}`,
      headers: authHeaders,
    });
    expect(revokeRes.statusCode).toBe(200);

    const afterRevoke = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      headers: { Authorization: `Bearer ${fullKeyBody.key}` },
      payload: {},
    });
    expect(afterRevoke.statusCode).toBe(401);
    expect(afterRevoke.json().error.code).toBe('INVALID_API_KEY');
  });

  it('skips Turnstile CAPTCHA in production for API key requests and enforces daily 429 rate limit with Retry-After', async () => {
    const { app, authStore } = await buildApiKeyApp({ nodeEnv: 'production', dailyLimit: 2 });

    // Create verified user directly in store and log in (production cookie is __Host-tm_session)
    const { hashPassword } = await import('../src/auth/password.js');
    const user = await authStore.createUser({
      email: 'prod@example.com',
      passwordHash: await hashPassword('prod strong passphrase 123'),
      emailVerifiedAt: new Date(),
      planId: 'free',
    });

    const login = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: user.email, password: 'prod strong passphrase 123' },
    });
    const cookie = extractCookieHeader(login.headers['set-cookie']);

    const keyRes = await app.inject({
      method: 'POST',
      url: '/api/v1/account/api-keys',
      headers: { cookie, 'x-requested-with': 'XMLHttpRequest' },
      payload: { name: 'Prod Key' },
    });
    expect(keyRes.statusCode).toBe(201);
    const { key, apiKey } = keyRes.json() as { key: string; apiKey: { id: string } };

    // Anonymous POST /inbox in production requires Turnstile (400)
    const anonNoCaptcha = await app.inject({ method: 'POST', url: '/api/v1/inbox', payload: {} });
    expect(anonNoCaptcha.statusCode).toBe(400);
    expect(anonNoCaptcha.json().error.code).toBe('CAPTCHA_REQUIRED');

    // API key skips Turnstile -> 201 for first 2 requests
    const r1 = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      headers: { Authorization: `Bearer ${key}` },
      payload: {},
    });
    const r2 = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      headers: { Authorization: `Bearer ${key}` },
      payload: {},
    });
    expect(r1.statusCode).toBe(201);
    expect(r2.statusCode).toBe(201);

    // 3rd request exceeds daily limit (2) -> 429 with Retry-After header
    const r3 = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      headers: { Authorization: `Bearer ${key}` },
      payload: {},
    });
    expect(r3.statusCode).toBe(429);
    expect(r3.json().error.code).toBe('API_KEY_RATE_LIMIT_EXCEEDED');
    expect(Number(r3.headers['retry-after'])).toBeGreaterThan(0);

    // Usage endpoint records daily count
    await new Promise((r) => setTimeout(r, 20));
    const usageRes = await app.inject({
      method: 'GET',
      url: `/api/v1/account/api-keys/${apiKey.id}/usage`,
      headers: { cookie },
    });
    expect(usageRes.statusCode).toBe(200);
    const usage = (usageRes.json() as { usage: Array<{ day: string; count: number }> }).usage;
    expect(usage[0]?.count).toBe(2);
  });
});
