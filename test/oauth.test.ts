import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { createApiApp } from '../src/api/app.js';
import type { GoogleOAuthClient, VerifiedGoogleIdentity } from '../src/auth/googleOAuth.js';
import { loadEnv } from '../src/config/env.js';
import type { Mailer } from '../src/mail/mailer.js';
import type {
  AuthStore,
  EmailTokenRecord,
  OAuthAccountRecord,
  UserRecord,
} from '../src/storage/authStore.js';
import { DEFAULT_PLAN_LIMITS, type PlanLimits } from '../src/storage/plans.js';
import { createLogger } from '../src/utils/logger.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

function createMemoryAuthStore() {
  const usersById = new Map<string, UserRecord>();
  const usersByEmail = new Map<string, string>();
  const oauthByKey = new Map<string, OAuthAccountRecord>();
  const tokensByHash = new Map<string, EmailTokenRecord>();

  const store: AuthStore = {
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
      const rec = tokensByHash.get(tokenHash);
      if (!rec || rec.type !== type || rec.usedAt) return null;
      return rec;
    },
    async findOAuthAccount(provider, providerUserId) {
      return oauthByKey.get(`${provider}:${providerUserId}`) ?? null;
    },
    async linkOAuthAccount(input) {
      const rec: OAuthAccountRecord = {
        id: randomUUID(),
        userId: input.userId,
        provider: input.provider,
        providerUserId: input.providerUserId,
        email: input.email.toLowerCase(),
        createdAt: new Date(),
      };
      oauthByKey.set(`${input.provider}:${input.providerUserId}`, rec);
      return rec;
    },
    async unlinkOAuthAccount(userId, provider) {
      for (const [k, v] of oauthByKey.entries()) {
        if (v.userId === userId && v.provider === provider) {
          oauthByKey.delete(k);
          return true;
        }
      }
      return false;
    },
    async listOAuthAccounts(userId) {
      return Array.from(oauthByKey.values()).filter((v) => v.userId === userId);
    },
    async setTotpSecret() {},
    async getTotpSecret() {
      return null;
    },
    async enableTotp() {},
    async disableTotp() {},
    async replaceRecoveryCodes() {},
    async consumeRecoveryCode() {
      return false;
    },
    async loadPlansMap() {
      return new Map<string, PlanLimits>([
        ['anonymous', DEFAULT_PLAN_LIMITS.anonymous],
        ['free', DEFAULT_PLAN_LIMITS.free],
        ['premium', DEFAULT_PLAN_LIMITS.premium],
      ]);
    },
  };

  return { store, oauthByKey };
}

function extractCookieHeader(setCookieHeader: string | string[] | undefined): string {
  const first = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
  return first ? (first.split(';')[0] ?? '') : '';
}

describe('Phase B4: Google OAuth (PKCE + ID token + linking rules)', () => {
  const openApps: FastifyInstance[] = [];

  afterEach(async () => {
    while (openApps.length > 0) {
      const app = openApps.pop();
      if (app) await app.close();
    }
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  async function buildOAuthApp(identityFactory: (expectedNonce: string) => VerifiedGoogleIdentity) {
    const redis = createMockRedis();
    const { store: authStore, oauthByKey } = createMemoryAuthStore();
    const mailer: Mailer = {
      async sendEmail() {
        return { messageId: 'm1' };
      },
      close() {},
    };

    const googleOAuthClient: GoogleOAuthClient = {
      async exchangeCode({ code }) {
        if (code === 'bad-code') {
          throw new Error('invalid_grant');
        }
        return { idToken: `mock-id-token-${code}` };
      },
      async verifyIdToken(_idToken, expectedNonce) {
        const identity = identityFactory(expectedNonce);
        if (identity.nonce !== expectedNonce) {
          throw new Error('Google ID token nonce mismatch');
        }
        return identity;
      },
    };

    const config = loadEnv({
      NODE_ENV: 'test',
      APP_BASE_URL: 'https://temporamail.app',
      GOOGLE_CLIENT_ID: 'google-client-123',
      GOOGLE_CLIENT_SECRET: 'google-secret-456',
    });
    const logger = createLogger('oauth-test', 'silent', 'test');
    const app = await createApiApp({
      config,
      redis,
      logger,
      authStore,
      mailer,
      googleOAuthClient,
    });
    openApps.push(app);
    return { app, authStore, oauthByKey };
  }

  it('initiates PKCE redirect, creates a new verified Google user, sets session cookie, and rejects state replay', async () => {
    const { app, oauthByKey } = await buildOAuthApp((nonce) => ({
      sub: 'google-sub-1',
      email: 'dana@gmail.com',
      emailVerified: true,
      nonce,
    }));

    const startRes = await app.inject({ method: 'GET', url: '/api/v1/auth/google' });
    expect(startRes.statusCode).toBe(302);
    const location = startRes.headers.location ?? '';
    const redirectUrl = new URL(location);
    expect(redirectUrl.origin).toBe('https://accounts.google.com');
    expect(redirectUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(redirectUrl.searchParams.get('scope')).toBe('openid email profile');
    const state = redirectUrl.searchParams.get('state') ?? '';
    expect(state.length).toBeGreaterThan(20);

    // Valid callback creates user, sets session cookie, redirects to /dashboard
    const cbRes = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/google/callback?code=auth-code-1&state=${encodeURIComponent(state)}`,
    });
    expect(cbRes.statusCode).toBe(302);
    expect(cbRes.headers.location).toBe('https://temporamail.app/dashboard');
    const cookie = extractCookieHeader(cbRes.headers['set-cookie']);
    expect(cookie).toContain('tm_session=');
    expect(oauthByKey.has('google:google-sub-1')).toBe(true);

    // Replaying the same state is rejected (single-use)
    const replayRes = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/google/callback?code=auth-code-1&state=${encodeURIComponent(state)}`,
    });
    expect(replayRes.statusCode).toBe(400);
    expect(replayRes.json().error.code).toBe('INVALID_OAUTH_STATE');

    // Google-only user cannot unlink Google until they set a password
    const unlinkBlocked = await app.inject({
      method: 'DELETE',
      url: '/api/v1/account/oauth/google',
      headers: { cookie, 'x-requested-with': 'XMLHttpRequest' },
    });
    expect(unlinkBlocked.statusCode).toBe(400);
    expect(unlinkBlocked.json().error.code).toBe('CANNOT_UNLINK_LAST_LOGIN_METHOD');
  });

  it('rejects bad nonce and unverified Google emails', async () => {
    // Bad nonce
    const { app: badNonceApp } = await buildOAuthApp(() => ({
      sub: 'google-sub-2',
      email: 'eve@gmail.com',
      emailVerified: true,
      nonce: 'wrong-nonce',
    }));
    const s1 = await badNonceApp.inject({ method: 'GET', url: '/api/v1/auth/google' });
    const state1 = new URL(s1.headers.location ?? '').searchParams.get('state') ?? '';
    const cb1 = await badNonceApp.inject({
      method: 'GET',
      url: `/api/v1/auth/google/callback?code=c1&state=${encodeURIComponent(state1)}`,
    });
    expect(cb1.statusCode).toBe(401);
    expect(cb1.json().error.code).toBe('INVALID_ID_TOKEN');

    // Unverified Google email
    const { app: unverifiedApp } = await buildOAuthApp((nonce) => ({
      sub: 'google-sub-3',
      email: 'unverified@gmail.com',
      emailVerified: false,
      nonce,
    }));
    const s2 = await unverifiedApp.inject({ method: 'GET', url: '/api/v1/auth/google' });
    const state2 = new URL(s2.headers.location ?? '').searchParams.get('state') ?? '';
    const cb2 = await unverifiedApp.inject({
      method: 'GET',
      url: `/api/v1/auth/google/callback?code=c2&state=${encodeURIComponent(state2)}`,
    });
    expect(cb2.statusCode).toBe(403);
    expect(cb2.json().error.code).toBe('GOOGLE_EMAIL_UNVERIFIED');
  });

  it('links to an existing verified user but refuses linking to an unverified local user', async () => {
    const { app, authStore, oauthByKey } = await buildOAuthApp((nonce) => ({
      sub: 'google-sub-4',
      email: 'frank@example.com',
      emailVerified: true,
      nonce,
    }));

    // Create UNVERIFIED local user with same email
    const localUser = await authStore.createUser({
      email: 'frank@example.com',
      passwordHash: 'hashed-pw',
      emailVerifiedAt: null,
    });

    const s1 = await app.inject({ method: 'GET', url: '/api/v1/auth/google' });
    const state1 = new URL(s1.headers.location ?? '').searchParams.get('state') ?? '';
    const conflictRes = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/google/callback?code=c1&state=${encodeURIComponent(state1)}`,
    });
    expect(conflictRes.statusCode).toBe(409);
    expect(conflictRes.json().error.code).toBe('ACCOUNT_UNVERIFIED_CONFLICT');
    expect(oauthByKey.size).toBe(0);

    // Once verified, linking succeeds!
    await authStore.markEmailVerified(localUser.id);
    const s2 = await app.inject({ method: 'GET', url: '/api/v1/auth/google' });
    const state2 = new URL(s2.headers.location ?? '').searchParams.get('state') ?? '';
    const linkedRes = await app.inject({
      method: 'GET',
      url: `/api/v1/auth/google/callback?code=c2&state=${encodeURIComponent(state2)}`,
    });
    expect(linkedRes.statusCode).toBe(302);
    expect(oauthByKey.get('google:google-sub-4')?.userId).toBe(localUser.id);
  });
});
