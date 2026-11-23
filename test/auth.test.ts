import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { createApiApp } from '../src/api/app.js';
import { hashPassword, validatePasswordStrength, verifyPassword } from '../src/auth/password.js';
import { loadEnv } from '../src/config/env.js';
import type { Mailer } from '../src/mail/mailer.js';
import type { EmailTemplateDataMap, EmailTemplateName } from '../src/mail/templates.js';
import type { AuthStore, EmailTokenRecord, UserRecord } from '../src/storage/authStore.js';
import { DEFAULT_PLAN_LIMITS, type PlanLimits } from '../src/storage/plans.js';
import { createLogger } from '../src/utils/logger.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

interface SentEmail {
  readonly to: string;
  readonly template: EmailTemplateName;
  readonly data: unknown;
}

function createMemoryAuthStore(): AuthStore {
  const usersById = new Map<string, UserRecord>();
  const usersByEmail = new Map<string, string>();
  const tokensByHash = new Map<string, EmailTokenRecord>();

  return {
    async findUserByEmail(email) {
      const id = usersByEmail.get(email.trim().toLowerCase());
      return id ? (usersById.get(id) ?? null) : null;
    },
    async findUserById(id) {
      return usersById.get(id) ?? null;
    },
    async createUser(input) {
      const email = input.email.trim().toLowerCase();
      const user: UserRecord = {
        id: randomUUID(),
        email,
        passwordHash: input.passwordHash,
        emailVerifiedAt: input.emailVerifiedAt ?? null,
        planId: input.planId ?? 'free',
        status: 'active',
        totpEnabled: false,
        createdAt: new Date(),
        lastLoginAt: null,
      };
      usersById.set(user.id, user);
      usersByEmail.set(email, user.id);
      return user;
    },
    async markEmailVerified(userId) {
      const existing = usersById.get(userId);
      if (!existing) return null;
      const updated: UserRecord = { ...existing, emailVerifiedAt: new Date() };
      usersById.set(userId, updated);
      return updated;
    },
    async updatePasswordHash(userId, passwordHash) {
      const existing = usersById.get(userId);
      if (!existing) return;
      usersById.set(userId, { ...existing, passwordHash });
    },
    async updateLastLogin(userId) {
      const existing = usersById.get(userId);
      if (!existing) return;
      usersById.set(userId, { ...existing, lastLoginAt: new Date() });
    },
    async deleteUser(userId) {
      const existing = usersById.get(userId);
      if (existing) {
        usersByEmail.delete(existing.email);
        usersById.delete(userId);
      }
    },
    async createEmailToken(input) {
      const record: EmailTokenRecord = {
        id: randomUUID(),
        userId: input.userId,
        type: input.type,
        targetEmail: input.targetEmail ?? null,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        usedAt: null,
      };
      tokensByHash.set(input.tokenHash, record);
      return record;
    },
    async consumeEmailToken(tokenHash, type) {
      const record = tokensByHash.get(tokenHash);
      if (!record || record.type !== type || record.usedAt !== null) {
        return null;
      }
      if (record.expiresAt.getTime() < Date.now()) {
        return null;
      }
      const consumed: EmailTokenRecord = { ...record, usedAt: new Date() };
      tokensByHash.set(tokenHash, consumed);
      return consumed;
    },
    async loadPlansMap() {
      return new Map<string, PlanLimits>([
        ['anonymous', DEFAULT_PLAN_LIMITS.anonymous],
        ['free', DEFAULT_PLAN_LIMITS.free],
        ['premium', DEFAULT_PLAN_LIMITS.premium],
      ]);
    },
  };
}

function extractCookieHeader(setCookieHeader: string | string[] | undefined): string {
  const first = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
  if (!first) return '';
  return first.split(';')[0] ?? '';
}

describe('Phase B3: Email + Password Auth & Redis Sessions', () => {
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

  async function buildAuthApp() {
    const redis = createMockRedis();
    const authStore = createMemoryAuthStore();
    const sentEmails: SentEmail[] = [];

    const mailer: Mailer = {
      async sendEmail<T extends EmailTemplateName>(
        to: string,
        template: T,
        data: EmailTemplateDataMap[T],
      ) {
        sentEmails.push({ to, template, data });
        return { messageId: `msg-${sentEmails.length}` };
      },
      close() {},
    };

    const config = loadEnv({
      NODE_ENV: 'test',
      ALLOWED_DOMAINS: 'temporamail.app,alt.temporamail.app',
      APP_BASE_URL: 'https://temporamail.app',
    });
    const logger = createLogger('auth-test', 'silent', 'test');
    const app = await createApiApp({
      config,
      redis,
      logger,
      authStore,
      mailer,
    });
    openApps.push(app);
    return { app, redis, authStore, sentEmails };
  }

  it('hashes passwords with argon2id and rejects short or common passwords', async () => {
    expect(validatePasswordStrength('short123').valid).toBe(false);
    expect(validatePasswordStrength('password123').valid).toBe(false);
    expect(validatePasswordStrength('aaaaaaaaaaaa').valid).toBe(false);
    expect(validatePasswordStrength('correct horse battery staple').valid).toBe(true);

    const hash = await hashPassword('correct horse battery staple');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(hash, 'correct horse battery staple')).toBe(true);
    expect(await verifyPassword(hash, 'wrong passphrase')).toBe(false);
  });

  it('blocks disposable email domains and own temp domains on signup', async () => {
    const { app } = await buildAuthApp();

    const ownTemp = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'user@temporamail.app', password: 'correct horse battery staple' },
    });
    expect(ownTemp.statusCode).toBe(400);
    expect(ownTemp.json().error.code).toBe('DISPOSABLE_EMAIL_NOT_ALLOWED');

    const disposable = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'user@mailinator.com', password: 'correct horse battery staple' },
    });
    expect(disposable.statusCode).toBe(400);
    expect(disposable.json().error.code).toBe('DISPOSABLE_EMAIL_NOT_ALLOWED');
  });

  it('completes signup, single-use email verification, session cookie auth, and CSRF enforcement', async () => {
    const { app, sentEmails } = await buildAuthApp();

    const signup = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'alice@example.com', password: 'correct horse battery staple' },
    });
    expect(signup.statusCode).toBe(202);
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0]?.template).toBe('verify_email');

    const verifyData = sentEmails[0]?.data as { verifyUrl: string };
    const token = new URL(verifyData.verifyUrl).searchParams.get('token');
    expect(token).toBeTruthy();

    // Verify email -> sets HttpOnly session cookie
    const verifyRes = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/verify?token=${encodeURIComponent(token ?? '')}`,
    });
    expect(verifyRes.statusCode).toBe(200);
    expect(verifyRes.json()).toMatchObject({
      verified: true,
      user: { email: 'alice@example.com', emailVerified: true },
    });

    const cookieHeader = extractCookieHeader(verifyRes.headers['set-cookie']);
    expect(cookieHeader).toContain('tm_session=');

    // Reusing the same single-use token fails
    const reuseRes = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/verify?token=${encodeURIComponent(token ?? '')}`,
    });
    expect(reuseRes.statusCode).toBe(400);
    expect(reuseRes.json().error.code).toBe('INVALID_TOKEN');

    // GET /account/me returns profile + entitlements
    const meRes = await app.inject({
      method: 'GET',
      url: '/api/v1/account/me',
      headers: { cookie: cookieHeader },
    });
    expect(meRes.statusCode).toBe(200);
    expect(meRes.json().entitlements).toMatchObject({
      planId: 'free',
      maxActiveAddresses: 3,
      maxApiKeys: 2,
    });

    // POST /auth/logout without CSRF header -> 403
    const noCsrf = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/logout',
      headers: { cookie: cookieHeader },
    });
    expect(noCsrf.statusCode).toBe(403);
    expect(noCsrf.json().error.code).toBe('CSRF_REQUIRED');

    // POST /auth/logout with CSRF header -> 200 and invalidates session
    const logoutOk = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/logout',
      headers: { cookie: cookieHeader, 'x-requested-with': 'XMLHttpRequest' },
    });
    expect(logoutOk.statusCode).toBe(200);

    const meAfterLogout = await app.inject({
      method: 'GET',
      url: '/api/v1/account/me',
      headers: { cookie: cookieHeader },
    });
    expect(meAfterLogout.statusCode).toBe(401);
  });

  it('enforces enumeration-safe login errors and locks out after 5 failed attempts', async () => {
    const { app } = await buildAuthApp();

    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'bob@example.com', password: 'my super secret passphrase' },
    });

    // Unknown email vs wrong password return identical error message
    const unknownRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'nobody@example.com', password: 'wrong password here' },
    });
    expect(unknownRes.statusCode).toBe(401);

    const wrongPwRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'bob@example.com', password: 'wrong password here' },
    });
    expect(wrongPwRes.statusCode).toBe(401);
    expect(wrongPwRes.json()).toEqual(unknownRes.json());

    // 4 more wrong attempts -> 5th triggers 429 lockout
    for (let i = 0; i < 3; i += 1) {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'bob@example.com', password: 'wrong password here' },
      });
    }
    const lockedRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'bob@example.com', password: 'wrong password here' },
    });
    expect(lockedRes.statusCode).toBe(429);
    expect(lockedRes.json().error.code).toBe('ACCOUNT_LOCKED');
  });

  it('resets password with single-use token and invalidates all existing sessions', async () => {
    const { app, sentEmails } = await buildAuthApp();

    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'carol@example.com', password: 'initial strong passphrase' },
    });

    // Log in to get an active session
    const loginRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'carol@example.com', password: 'initial strong passphrase' },
    });
    expect(loginRes.statusCode).toBe(200);
    const cookieHeader = extractCookieHeader(loginRes.headers['set-cookie']);

    // Forgot password (always generic response)
    const forgotRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/forgot-password',
      payload: { email: 'carol@example.com' },
    });
    expect(forgotRes.statusCode).toBe(200);
    expect(forgotRes.json().message).toContain('If that account exists');

    const resetEmail = sentEmails.find((e) => e.template === 'reset_password');
    expect(resetEmail).toBeDefined();
    const resetToken = new URL((resetEmail?.data as { resetUrl: string }).resetUrl).searchParams.get(
      'token',
    );
    expect(resetToken).toBeTruthy();

    // Complete reset
    const resetRes = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/reset-password',
      payload: { token: resetToken, newPassword: 'brand new strong passphrase' },
    });
    expect(resetRes.statusCode).toBe(200);

    // Previous session is now invalidated
    const meOldSession = await app.inject({
      method: 'GET',
      url: '/api/v1/account/me',
      headers: { cookie: cookieHeader },
    });
    expect(meOldSession.statusCode).toBe(401);

    // Can log in with the new password
    const newLogin = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'carol@example.com', password: 'brand new strong passphrase' },
    });
    expect(newLogin.statusCode).toBe(200);
  });
});
