import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import type { SMTPServer } from 'smtp-server';
import { createApiApp } from '../src/api/app.js';
import { loadEnv } from '../src/config/env.js';
import { processIncomingMessage } from '../src/pipeline/processMessage.js';
import { createSmtpServer } from '../src/smtp/server.js';
import { createLogger } from '../src/utils/logger.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

async function sendRawSmtpEmail(port: number, from: string, to: string, rawBody: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    socket.setEncoding('utf8');
    let buffer = '';
    const steps = [
      `EHLO test.example.com\r\n`,
      `MAIL FROM:<${from}>\r\n`,
      `RCPT TO:<${to}>\r\n`,
      `DATA\r\n`,
      `${rawBody}\r\n.\r\n`,
      `QUIT\r\n`,
    ];
    let stepIndex = 0;

    socket.on('error', reject);
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      while (buffer.includes('\r\n')) {
        const idx = buffer.indexOf('\r\n');
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        if (/^\d{3} /.test(line)) {
          if (line.startsWith('4') || line.startsWith('5')) {
            socket.destroy();
            reject(new Error(`SMTP rejected: ${line}`));
            return;
          }
          const next = steps[stepIndex];
          stepIndex += 1;
          if (next) {
            socket.write(next);
          } else {
            socket.destroy();
            resolve();
          }
        }
      }
    });
  });
}

describe('Step 3: REST API (/api/v1)', () => {
  const openApps: FastifyInstance[] = [];
  const openServers: SMTPServer[] = [];

  afterEach(async () => {
    while (openApps.length > 0) {
      const app = openApps.pop();
      if (app) {
        await app.close();
      }
    }
    while (openServers.length > 0) {
      const srv = openServers.pop();
      if (srv) {
        await new Promise<void>((resolve) => srv.close(() => resolve()));
      }
    }
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  async function buildTestApp(overrides: NodeJS.ProcessEnv = {}) {
    const redis = createMockRedis();
    const config = loadEnv({
      NODE_ENV: 'test',
      ALLOWED_DOMAINS: 'temporamail.app,alt.temporamail.app',
      DEFAULT_TTL_MINUTES: '10',
      MAX_TTL_MINUTES: '60',
      INBOX_CREATE_LIMIT_PER_HOUR: '10',
      API_RATE_LIMIT_PER_MIN: '120',
      ...overrides,
    });
    const logger = createLogger('api-test', 'silent', 'test');
    const app = await createApiApp({ config, redis, logger });
    openApps.push(app);
    return { app, redis, config, logger };
  }

  it('serves /health, /domains, and consistent 404 errors', async () => {
    const { app } = await buildTestApp();

    const health = await app.inject({ method: 'GET', url: '/api/v1/health' });
    expect(health.statusCode).toBe(200);
    expect(health.json()).toMatchObject({ status: 'ok', redis: 'up' });

    const domains = await app.inject({ method: 'GET', url: '/api/v1/domains' });
    expect(domains.statusCode).toBe(200);
    expect(domains.json()).toEqual({ domains: ['temporamail.app', 'alt.temporamail.app'] });

    const missing = await app.inject({ method: 'GET', url: '/api/v1/does-not-exist' });
    expect(missing.statusCode).toBe(404);
    expect(missing.json()).toEqual({
      error: { code: 'NOT_FOUND', message: 'Route not found' },
    });
  });

  it('creates an inbox, validates inputs, enforces ownerToken on extend/delete', async () => {
    const { app } = await buildTestApp();

    // Validation errors
    const badDomain = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      payload: { domain: 'evil.com' },
    });
    expect(badDomain.statusCode).toBe(400);
    expect(badDomain.json().error.code).toBe('INVALID_DOMAIN');

    const badTtl = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      payload: { ttlMinutes: 999 },
    });
    expect(badTtl.statusCode).toBe(400);
    expect(badTtl.json().error.code).toBe('TTL_EXCEEDS_MAX');

    // Create inbox
    const created = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      payload: { domain: 'alt.temporamail.app', ttlMinutes: 15 },
    });
    expect(created.statusCode).toBe(201);
    const createdBody = created.json() as {
      address: string;
      ownerToken: string;
      expiresAt: string;
    };
    expect(createdBody.address.endsWith('@alt.temporamail.app')).toBe(true);
    expect(createdBody.ownerToken).toMatch(/^[0-9a-f]{64}$/);

    // Get status
    const status = await app.inject({
      method: 'GET',
      url: `/api/v1/inbox/${encodeURIComponent(createdBody.address)}`,
    });
    expect(status.statusCode).toBe(200);
    expect(status.json()).toMatchObject({
      address: createdBody.address,
      messageCount: 0,
    });

    // Extend without token -> 401
    const unauthExtend = await app.inject({
      method: 'POST',
      url: `/api/v1/inbox/${encodeURIComponent(createdBody.address)}/extend`,
      payload: { ttlMinutes: 10 },
    });
    expect(unauthExtend.statusCode).toBe(401);
    expect(unauthExtend.json().error.code).toBe('UNAUTHORIZED');

    // Extend with valid token, capped at MAX_TTL_MINUTES (60)
    const extended = await app.inject({
      method: 'POST',
      url: `/api/v1/inbox/${encodeURIComponent(createdBody.address)}/extend`,
      headers: { 'x-owner-token': createdBody.ownerToken },
      payload: { ttlMinutes: 120 },
    });
    expect(extended.statusCode).toBe(200);
    expect((extended.json() as { ttlSeconds: number }).ttlSeconds).toBeLessThanOrEqual(3600);

    // Delete with wrong token -> 401
    const wrongDel = await app.inject({
      method: 'DELETE',
      url: `/api/v1/inbox/${encodeURIComponent(createdBody.address)}`,
      headers: { 'x-owner-token': 'deadbeef' },
    });
    expect(wrongDel.statusCode).toBe(401);

    // Delete with valid token -> 200
    const del = await app.inject({
      method: 'DELETE',
      url: `/api/v1/inbox/${encodeURIComponent(createdBody.address)}`,
      headers: { 'x-owner-token': createdBody.ownerToken },
    });
    expect(del.statusCode).toBe(200);
    expect(del.json()).toEqual({ deleted: true });

    // Confirm deleted -> 404
    const afterDel = await app.inject({
      method: 'GET',
      url: `/api/v1/inbox/${encodeURIComponent(createdBody.address)}`,
    });
    expect(afterDel.statusCode).toBe(404);
  });

  it('enforces per-IP rate limits on POST /inbox with consistent 429 error shape', async () => {
    const { app } = await buildTestApp({ INBOX_CREATE_LIMIT_PER_HOUR: '2' });

    const r1 = await app.inject({ method: 'POST', url: '/api/v1/inbox', payload: {} });
    const r2 = await app.inject({ method: 'POST', url: '/api/v1/inbox', payload: {} });
    const r3 = await app.inject({ method: 'POST', url: '/api/v1/inbox', payload: {} });

    expect(r1.statusCode).toBe(201);
    expect(r2.statusCode).toBe(201);
    expect(r3.statusCode).toBe(429);
    expect(r3.json().error.code).toBe('RATE_LIMIT_EXCEEDED');
  });

  it('requires Turnstile token on POST /inbox in production mode', async () => {
    const redis = createMockRedis();
    const config = loadEnv({
      NODE_ENV: 'production',
      ALLOWED_DOMAINS: 'temporamail.app',
    });
    const logger = createLogger('api-prod-test', 'silent', 'test');
    const app = await createApiApp({
      config,
      redis,
      logger,
      verifyTurnstile: async (token) => token === 'valid-token',
    });
    openApps.push(app);

    const missing = await app.inject({ method: 'POST', url: '/api/v1/inbox', payload: {} });
    expect(missing.statusCode).toBe(400);
    expect(missing.json().error.code).toBe('CAPTCHA_REQUIRED');

    const invalid = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      payload: { turnstileToken: 'bad-token' },
    });
    expect(invalid.statusCode).toBe(403);
    expect(invalid.json().error.code).toBe('CAPTCHA_FAILED');

    const ok = await app.inject({
      method: 'POST',
      url: '/api/v1/inbox',
      payload: { turnstileToken: 'valid-token' },
    });
    expect(ok.statusCode).toBe(201);
  });

  it('integration: delivers email via SMTP and reads message + attachment via REST API', async () => {
    const { app, redis, config, logger } = await buildTestApp();

    const smtpServer = createSmtpServer({
      config,
      redis,
      logger,
      hooks: {
        async onMessage(message) {
          await processIncomingMessage(message, { config, redis, logger });
        },
      },
    });
    openServers.push(smtpServer);

    const smtpPort = await new Promise<number>((resolve, reject) => {
      smtpServer.listen(0, '127.0.0.1', () => {
        const addr = smtpServer.server.address() as AddressInfo | null;
        if (!addr) {
          reject(new Error('No SMTP port'));
          return;
        }
        resolve(addr.port);
      });
    });

    // 1. Create inbox via API
    const created = await app.inject({ method: 'POST', url: '/api/v1/inbox', payload: {} });
    expect(created.statusCode).toBe(201);
    const { address, ownerToken } = created.json() as { address: string; ownerToken: string };

    // 2. Send real SMTP email with OTP + attachment
    const boundary = '----IntBoundary99';
    const rawEmail = [
      'From: GitHub <noreply@github.com>',
      `To: ${address}`,
      'Subject: Your GitHub verification code',
      'MIME-Version: 1.0',
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Your verification code is 649201.',
      `--${boundary}`,
      'Content-Type: text/plain; name="code.txt"',
      'Content-Disposition: attachment; filename="code.txt"',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('OTP=649201').toString('base64'),
      `--${boundary}--`,
    ].join('\r\n');

    await sendRawSmtpEmail(smtpPort, 'noreply@github.com', address, rawEmail);

    // 3. List messages via API
    const listRes = await app.inject({
      method: 'GET',
      url: `/api/v1/inbox/${encodeURIComponent(address)}/messages`,
    });
    expect(listRes.statusCode).toBe(200);
    const listBody = listRes.json() as {
      messages: Array<{ id: string; subject: string; hasOtp: boolean; attachmentCount: number }>;
    };
    expect(listBody.messages).toHaveLength(1);
    expect(listBody.messages[0]?.hasOtp).toBe(true);
    expect(listBody.messages[0]?.attachmentCount).toBe(1);

    const msgId = listBody.messages[0]?.id;
    expect(msgId).toBeDefined();

    // 4. Read full message via API
    const fullRes = await app.inject({
      method: 'GET',
      url: `/api/v1/inbox/${encodeURIComponent(address)}/messages/${msgId}`,
    });
    expect(fullRes.statusCode).toBe(200);
    expect(fullRes.json()).toMatchObject({
      id: msgId,
      subject: 'Your GitHub verification code',
      otp: '649201',
    });

    // 5. Download attachment via API with security headers
    const attRes = await app.inject({
      method: 'GET',
      url: `/api/v1/inbox/${encodeURIComponent(address)}/messages/${msgId}/attachments/0`,
    });
    expect(attRes.statusCode).toBe(200);
    expect(attRes.headers['content-disposition']).toBe('attachment; filename="code.txt"');
    expect(attRes.headers['x-content-type-options']).toBe('nosniff');
    expect(attRes.body).toBe('OTP=649201');

    // 6. Delete single message with ownerToken
    const delMsg = await app.inject({
      method: 'DELETE',
      url: `/api/v1/inbox/${encodeURIComponent(address)}/messages/${msgId}`,
      headers: { Authorization: `Bearer ${ownerToken}` },
    });
    expect(delMsg.statusCode).toBe(200);
    expect(delMsg.json()).toEqual({ deleted: true });

    const afterDelList = await app.inject({
      method: 'GET',
      url: `/api/v1/inbox/${encodeURIComponent(address)}/messages`,
    });
    expect((afterDelList.json() as { messages: unknown[] }).messages).toHaveLength(0);
  });
});
