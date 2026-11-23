import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { createApiApp } from '../src/api/app.js';
import {
  decryptTotpSecret,
  encryptTotpSecret,
  generateCurrentTotpCode,
} from '../src/auth/totp.js';
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

describe('Phase B5: User 2FA (TOTP + AES-256-GCM + Recovery Codes)', () => {
  const openApps: FastifyInstance[] = [];

  afterEach(async () => {
    while (openApps.length > 0) {
      const app = openApps.pop();
      if (app) await app.close();
    }
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  async function buildTwoFaApp() {
    const redis = createMockRedis();
    const { store: authStore, totpByUserId } = createMemoryAuthStore();
    const sentTemplates: string[] = [];
    const mailer: Mailer = {
      async sendEmail(_to, template) {
        sentTemplates.push(template);
        return { messageId: `m-${sentTemplates.length}` };
      },
      close() {},
    };

    const config = loadEnv({
      NODE_ENV: 'test',
      TOTP_ENCRYPTION_KEY: 'a'.repeat(64),
    });
    const logger = createLogger('2fa-test', 'silent', 'test');
    const app = await createApiApp({
      config,
      redis,
      logger,
      authStore,
      mailer,
    });
    openApps.push(app);
    return { app, redis, authStore, totpByUserId, sentTemplates };
  }

  it('encrypts and decrypts TOTP secrets with AES-256-GCM and rejects tampered ciphertext', () => {
    const key = 'b'.repeat(64);
    const encrypted = encryptTotpSecret('JBSWY3DPEHPK3PXP', key);
    expect(encrypted.startsWith('v1:')).toBe(true);
    expect(encrypted).not.toContain('JBSWY3DPEHPK3PXP');
    expect(decryptTotpSecret(encrypted, key)).toBe('JBSWY3DPEHPK3PXP');

    const tampered = `${encrypted.slice(0, -2)}00`;
    expect(() => decryptTotpSecret(tampered, key)).toThrow();
  });

  it('enrolls 2FA, logs in with TOTP and single-use recovery code, and disables 2FA', async () => {
    const { app, totpByUserId, sentTemplates } = await buildTwoFaApp();
    const password = 'my ultra strong passphrase';

    // 1. Signup & login
    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'mfa@example.com', password },
    });
    const login1 = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'mfa@example.com', password },
    });
    expect(login1.statusCode).toBe(200);
    let cookie = extractCookieHeader(login1.headers['set-cookie']);

    // 2. Setup 2FA -> secret encrypted at rest
    const setupRes = await app.inject({
      method: 'POST',
      url: '/api/v1/account/2fa/setup',
      headers: { cookie, 'x-requested-with': 'XMLHttpRequest' },
    });
    expect(setupRes.statusCode).toBe(200);
    const { secret, otpauthUrl } = setupRes.json() as { secret: string; otpauthUrl: string };
    expect(otpauthUrl).toContain('otpauth://totp/');
    const storedEncrypted = Array.from(totpByUserId.values())[0] ?? '';
    expect(storedEncrypted).not.toContain(secret);

    // 3. Enable 2FA with valid TOTP code -> returns 10 recovery codes once
    const enableCode = generateCurrentTotpCode(secret);
    const enableRes = await app.inject({
      method: 'POST',
      url: '/api/v1/account/2fa/enable',
      headers: { cookie, 'x-requested-with': 'XMLHttpRequest' },
      payload: { code: enableCode },
    });
    expect(enableRes.statusCode).toBe(200);
    const enableBody = enableRes.json() as { enabled: boolean; recoveryCodes: string[] };
    expect(enableBody.enabled).toBe(true);
    expect(enableBody.recoveryCodes).toHaveLength(10);
    expect(sentTemplates).toContain('2fa_enabled');
    cookie = extractCookieHeader(enableRes.headers['set-cookie']);

    // 4. Subsequent password login requires MFA step
    const mfaLogin = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'mfa@example.com', password },
    });
    expect(mfaLogin.statusCode).toBe(200);
    const { mfaRequired, mfaToken } = mfaLogin.json() as {
      mfaRequired: boolean;
      mfaToken: string;
    };
    expect(mfaRequired).toBe(true);
    expect(mfaToken).toBeTruthy();

    // 5. Complete login with valid TOTP code
    const totpCode = generateCurrentTotpCode(secret);
    const mfaOk = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login/mfa',
      payload: { mfaToken, code: totpCode },
    });
    expect(mfaOk.statusCode).toBe(200);
    expect(mfaOk.json()).toMatchObject({ authenticated: true, method: 'totp' });
    expect(extractCookieHeader(mfaOk.headers['set-cookie'])).toContain('tm_session=');

    // 6. Login again using a single-use recovery code
    const mfaLogin2 = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'mfa@example.com', password },
    });
    const mfaToken2 = (mfaLogin2.json() as { mfaToken: string }).mfaToken;
    const recoveryCode = enableBody.recoveryCodes[0] ?? '';

    const recoveryOk = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login/mfa',
      payload: { mfaToken: mfaToken2, code: recoveryCode },
    });
    expect(recoveryOk.statusCode).toBe(200);
    expect(recoveryOk.json()).toMatchObject({ authenticated: true, method: 'recovery' });
    cookie = extractCookieHeader(recoveryOk.headers['set-cookie']);

    // Reusing the same recovery code fails!
    const mfaLogin3 = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'mfa@example.com', password },
    });
    const mfaToken3 = (mfaLogin3.json() as { mfaToken: string }).mfaToken;
    const recoveryReuse = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login/mfa',
      payload: { mfaToken: mfaToken3, code: recoveryCode },
    });
    expect(recoveryReuse.statusCode).toBe(401);

    // 7. Disable 2FA requires password + valid code (using second recovery code)
    const disableRes = await app.inject({
      method: 'POST',
      url: '/api/v1/account/2fa/disable',
      headers: { cookie, 'x-requested-with': 'XMLHttpRequest' },
      payload: { password, code: enableBody.recoveryCodes[1] },
    });
    expect(disableRes.statusCode).toBe(200);
    expect(disableRes.json()).toEqual({ enabled: false });
  });
});
