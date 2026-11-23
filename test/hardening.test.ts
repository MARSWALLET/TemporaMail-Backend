import { Writable } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { createApiApp } from '../src/api/app.js';
import { loadEnv } from '../src/config/env.js';
import type { Mailer } from '../src/mail/mailer.js';
import { createLogger } from '../src/utils/logger.js';
import { createMemoryAuthStore } from './helpers/memoryAuthStore.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

function extractCookieHeader(setCookieHeader: string | string[] | undefined): string {
  const first = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
  return first ? (first.split(';')[0] ?? '') : '';
}

describe('Phase B9: Security Hardening', () => {
  const openApps: FastifyInstance[] = [];

  afterEach(async () => {
    while (openApps.length > 0) {
      const app = openApps.pop();
      if (app) await app.close();
    }
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  it('redacts passwords, tokens, API keys, cookies, and TOTP secrets from Pino logs', () => {
    const lines: string[] = [];
    const sink = new Writable({
      write(chunk, _enc, cb) {
        lines.push(chunk.toString('utf8'));
        cb();
      },
    });

    const logger = createLogger('hardening-test', 'info', 'production', sink);
    logger.info(
      {
        password: 'super-secret-password',
        token: 'raw-verify-token',
        apiKey: 'tm_live_secretvalue123456',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        req: {
          headers: {
            authorization: 'Bearer tm_live_secretvalue123456',
            cookie: '__Host-tm_session=abc123',
          },
        },
      },
      'Sensitive test event',
    );

    const output = lines.join('\n');
    expect(output).not.toContain('super-secret-password');
    expect(output).not.toContain('raw-verify-token');
    expect(output).not.toContain('tm_live_secretvalue123456');
    expect(output).not.toContain('JBSWY3DPEHPK3PXP');
    expect(output).not.toContain('abc123');
    expect(output).toContain('[REDACTED]');
  });

  it('defaults production CORS strictly to main and admin origins and blocks unknown origins', async () => {
    const redis = createMockRedis();
    const config = loadEnv({
      NODE_ENV: 'production',
      PRIMARY_DOMAIN: 'temporamail.app',
      TOTP_ENCRYPTION_KEY: 'a'.repeat(64),
    });

    expect(config.corsOrigins).toEqual([
      'https://temporamail.app',
      'https://admin.temporamail.app',
    ]);

    const logger = createLogger('cors-test', 'silent', 'test');
    const app = await createApiApp({ config, redis, logger });
    openApps.push(app);

    const allowedMain = await app.inject({
      method: 'GET',
      url: '/api/v1/domains',
      headers: { origin: 'https://temporamail.app' },
    });
    expect(allowedMain.statusCode).toBe(200);
    expect(allowedMain.headers['access-control-allow-origin']).toBe('https://temporamail.app');

    const allowedAdmin = await app.inject({
      method: 'GET',
      url: '/api/v1/domains',
      headers: { origin: 'https://admin.temporamail.app' },
    });
    expect(allowedAdmin.statusCode).toBe(200);
    expect(allowedAdmin.headers['access-control-allow-origin']).toBe(
      'https://admin.temporamail.app',
    );

    const blocked = await app.inject({
      method: 'GET',
      url: '/api/v1/domains',
      headers: { origin: 'https://evil.example.com' },
    });
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json().error.code).toBe('CORS_FORBIDDEN');
  });

  it('exports user account data via GET /api/v1/account/export without exposing secrets or hashes', async () => {
    const redis = createMockRedis();
    const { store: authStore } = createMemoryAuthStore();
    const mailer: Mailer = {
      async sendEmail() {
        return { messageId: 'm1' };
      },
      close() {},
    };

    const config = loadEnv({ NODE_ENV: 'test' });
    const logger = createLogger('export-test', 'silent', 'test');
    const app = await createApiApp({ config, redis, logger, authStore, mailer });
    openApps.push(app);

    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'gdpr@example.com', password: 'gdpr strong passphrase' },
    });
    const login = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'gdpr@example.com', password: 'gdpr strong passphrase' },
    });
    const cookie = extractCookieHeader(login.headers['set-cookie']);

    const exportRes = await app.inject({
      method: 'GET',
      url: '/api/v1/account/export',
      headers: { cookie },
    });
    expect(exportRes.statusCode).toBe(200);
    const body = exportRes.json() as {
      exportedAt: string;
      user: { email: string };
      activeSessions: unknown[];
    };
    expect(body.user.email).toBe('gdpr@example.com');
    expect(body.activeSessions.length).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(body)).not.toContain('passwordHash');
    expect(JSON.stringify(body)).not.toContain('$argon2id$');
  });
});
