import { randomUUID } from 'node:crypto';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import type { SMTPServer } from 'smtp-server';
import { createApiApp } from '../src/api/app.js';
import { loadEnv } from '../src/config/env.js';
import type { Mailer } from '../src/mail/mailer.js';
import { processIncomingMessage } from '../src/pipeline/processMessage.js';
import type { StoredMessage } from '../src/pipeline/types.js';
import { createSmtpServer } from '../src/smtp/server.js';
import type { AccountInboxStore, UserInboxRecord } from '../src/storage/accountInboxStore.js';
import { validateCustomName } from '../src/utils/customName.js';
import { createLogger } from '../src/utils/logger.js';
import { createMemoryAuthStore } from './helpers/memoryAuthStore.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

function createMemoryAccountInboxStore() {
  const reserved = new Set(['admin', 'support', 'postmaster', 'temporamail']);
  const inboxes = new Map<string, UserInboxRecord>();
  const messagesByInbox = new Map<string, StoredMessage[]>();

  const store: AccountInboxStore = {
    async isReservedName(name) {
      return reserved.has(name.trim().toLowerCase());
    },
    async listUserInboxes(userId) {
      const now = Date.now();
      return Array.from(inboxes.values()).filter(
        (i) => i.userId === userId && i.expiresAt.getTime() > now,
      );
    },
    async findActiveInboxByAddress(address) {
      const now = Date.now();
      const target = address.trim().toLowerCase();
      for (const inbox of inboxes.values()) {
        if (inbox.address === target && inbox.expiresAt.getTime() > now) {
          return inbox;
        }
      }
      return null;
    },
    async findUserInboxById(userId, inboxId) {
      const inbox = inboxes.get(inboxId);
      if (!inbox || inbox.userId !== userId || inbox.expiresAt.getTime() <= Date.now()) {
        return null;
      }
      return inbox;
    },
    async createUserInbox(input) {
      const record: UserInboxRecord = {
        id: randomUUID(),
        userId: input.userId,
        address: input.address.trim().toLowerCase(),
        customName: input.customName,
        createdAt: new Date(),
        expiresAt: input.expiresAt,
      };
      inboxes.set(record.id, record);
      return record;
    },
    async deleteUserInbox(userId, inboxId) {
      const inbox = inboxes.get(inboxId);
      if (!inbox || inbox.userId !== userId) {
        return null;
      }
      inboxes.delete(inboxId);
      messagesByInbox.delete(inboxId);
      return inbox;
    },
    async storeAccountMessage(input) {
      const list = messagesByInbox.get(input.inboxId) ?? [];
      list.unshift(input.message);
      messagesByInbox.set(input.inboxId, list);
    },
    async listAccountMessages(inboxId) {
      return [...(messagesByInbox.get(inboxId) ?? [])];
    },
    async getAccountMessage(inboxId, msgId) {
      return (messagesByInbox.get(inboxId) ?? []).find((m) => m.id === msgId) ?? null;
    },
    async purgeExpired(now = new Date()) {
      let deletedInboxes = 0;
      for (const [id, inbox] of inboxes.entries()) {
        if (inbox.expiresAt.getTime() <= now.getTime()) {
          inboxes.delete(id);
          messagesByInbox.delete(id);
          deletedInboxes += 1;
        }
      }
      return { deletedInboxes, deletedMessages: 0 };
    },
  };

  return { store, inboxes };
}

function extractCookieHeader(setCookieHeader: string | string[] | undefined): string {
  const first = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
  return first ? (first.split(';')[0] ?? '') : '';
}

async function sendSmtpCommandSequence(port: number, from: string, to: string, body: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    socket.setEncoding('utf8');
    let buf = '';
    const steps = [
      'EHLO test.example.com\r\n',
      `MAIL FROM:<${from}>\r\n`,
      `RCPT TO:<${to}>\r\n`,
      'DATA\r\n',
      `${body}\r\n.\r\n`,
      'QUIT\r\n',
    ];
    let step = 0;

    socket.on('error', reject);
    socket.on('data', (chunk: string) => {
      buf += chunk;
      while (buf.includes('\r\n')) {
        const idx = buf.indexOf('\r\n');
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        if (/^\d{3} /.test(line)) {
          if (line.startsWith('4') || line.startsWith('5')) {
            socket.destroy();
            resolve(line);
            return;
          }
          const cmd = steps[step++];
          if (cmd) {
            socket.write(cmd);
          } else {
            socket.destroy();
            resolve(line);
          }
        }
      }
    });
  });
}

describe('Phase B6: Account-Owned Inboxes, Custom Names & Dual-Store SMTP Routing', () => {
  const openApps: FastifyInstance[] = [];
  const openServers: SMTPServer[] = [];

  afterEach(async () => {
    while (openApps.length > 0) {
      const app = openApps.pop();
      if (app) await app.close();
    }
    while (openServers.length > 0) {
      const srv = openServers.pop();
      if (srv) await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  it('validates custom name syntax rules strictly', () => {
    expect(validateCustomName('alice.dev-1').valid).toBe(true);
    expect(validateCustomName('ab').valid).toBe(false); // too short
    expect(validateCustomName('-alice').valid).toBe(false); // leading punctuation
    expect(validateCustomName('alice.').valid).toBe(false); // trailing punctuation
    expect(validateCustomName('alice..bob').valid).toBe(false); // double dot
    expect(validateCustomName('alice_bob').valid).toBe(false); // underscore not allowed
  });

  it('enforces reserved names, plan limits, collisions, and releases custom names on delete', async () => {
    const redis = createMockRedis();
    const { store: authStore } = createMemoryAuthStore();
    const { store: accountInboxStore } = createMemoryAccountInboxStore();
    const mailer: Mailer = {
      async sendEmail() {
        return { messageId: 'm1' };
      },
      close() {},
    };

    const config = loadEnv({ NODE_ENV: 'test', ALLOWED_DOMAINS: 'temporamail.app' });
    const logger = createLogger('acct-inbox-test', 'silent', 'test');
    const app = await createApiApp({
      config,
      redis,
      logger,
      authStore,
      accountInboxStore,
      mailer,
    });
    openApps.push(app);

    // Signup + login user 1 (free plan: max 3 active, 1 custom name, 24h TTL)
    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'u1@example.com', password: 'strong user passphrase 1' },
    });
    const login1 = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'u1@example.com', password: 'strong user passphrase 1' },
    });
    const cookie1 = extractCookieHeader(login1.headers['set-cookie']);
    const authHeaders1 = { cookie: cookie1, 'x-requested-with': 'XMLHttpRequest' };

    // Reserved name rejected
    const reservedRes = await app.inject({
      method: 'POST',
      url: '/api/v1/account/inboxes',
      headers: authHeaders1,
      payload: { customName: 'admin' },
    });
    expect(reservedRes.statusCode).toBe(400);
    expect(reservedRes.json().error.code).toBe('RESERVED_NAME');

    // Lifetime exceeding free plan (1440 min) rejected
    const tooLongRes = await app.inject({
      method: 'POST',
      url: '/api/v1/account/inboxes',
      headers: authHeaders1,
      payload: { ttlMinutes: 2000 },
    });
    expect(tooLongRes.statusCode).toBe(403);
    expect(tooLongRes.json().error.code).toBe('PLAN_LIMIT_EXCEEDED');

    // Create 1st custom inbox
    const custom1 = await app.inject({
      method: 'POST',
      url: '/api/v1/account/inboxes',
      headers: authHeaders1,
      payload: { customName: 'my-inbox', ttlMinutes: 1440 },
    });
    expect(custom1.statusCode).toBe(201);
    const custom1Body = custom1.json() as { id: string; address: string };
    expect(custom1Body.address).toBe('my-inbox@temporamail.app');

    // 2nd custom name on free plan rejected (limit = 1)
    const custom2 = await app.inject({
      method: 'POST',
      url: '/api/v1/account/inboxes',
      headers: authHeaders1,
      payload: { customName: 'second-name' },
    });
    expect(custom2.statusCode).toBe(403);

    // Create 2 random inboxes (total 3 = free plan max)
    expect(
      (
        await app.inject({
          method: 'POST',
          url: '/api/v1/account/inboxes',
          headers: authHeaders1,
          payload: {},
        })
      ).statusCode,
    ).toBe(201);
    expect(
      (
        await app.inject({
          method: 'POST',
          url: '/api/v1/account/inboxes',
          headers: authHeaders1,
          payload: {},
        })
      ).statusCode,
    ).toBe(201);

    // 4th inbox exceeds free plan limit (3)
    const fourth = await app.inject({
      method: 'POST',
      url: '/api/v1/account/inboxes',
      headers: authHeaders1,
      payload: {},
    });
    expect(fourth.statusCode).toBe(403);

    // User 2 cannot claim 'my-inbox' while User 1 owns it
    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'u2@example.com', password: 'strong user passphrase 2' },
    });
    const login2 = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'u2@example.com', password: 'strong user passphrase 2' },
    });
    const authHeaders2 = {
      cookie: extractCookieHeader(login2.headers['set-cookie']),
      'x-requested-with': 'XMLHttpRequest',
    };

    const collision = await app.inject({
      method: 'POST',
      url: '/api/v1/account/inboxes',
      headers: authHeaders2,
      payload: { customName: 'my-inbox' },
    });
    expect(collision.statusCode).toBe(409);
    expect(collision.json().error.code).toBe('ADDRESS_TAKEN');

    // User 1 deletes 'my-inbox' -> released -> User 2 can now claim it
    const del = await app.inject({
      method: 'DELETE',
      url: `/api/v1/account/inboxes/${custom1Body.id}`,
      headers: authHeaders1,
    });
    expect(del.statusCode).toBe(200);

    const reclaimed = await app.inject({
      method: 'POST',
      url: '/api/v1/account/inboxes',
      headers: authHeaders2,
      payload: { customName: 'my-inbox' },
    });
    expect(reclaimed.statusCode).toBe(201);
  });

  it('SMTP accepts active account address, routes to account_messages, and rejects expired account address', async () => {
    const redis = createMockRedis();
    const { store: authStore } = createMemoryAuthStore();
    const { store: accountInboxStore, inboxes } = createMemoryAccountInboxStore();
    const mailer: Mailer = {
      async sendEmail() {
        return { messageId: 'm1' };
      },
      close() {},
    };
    const config = loadEnv({ NODE_ENV: 'test', ALLOWED_DOMAINS: 'temporamail.app' });
    const logger = createLogger('acct-smtp-test', 'silent', 'test');

    const app = await createApiApp({
      config,
      redis,
      logger,
      authStore,
      accountInboxStore,
      mailer,
    });
    openApps.push(app);

    const smtpServer = createSmtpServer({
      config,
      redis,
      logger,
      hooks: {
        hasAccountInbox: async (addr) =>
          (await accountInboxStore.findActiveInboxByAddress(addr)) !== null,
        async onMessage(message) {
          await processIncomingMessage(message, {
            config,
            redis,
            logger,
            accountInboxStore,
          });
        },
      },
    });
    openServers.push(smtpServer);

    const smtpPort = await new Promise<number>((resolve, reject) => {
      smtpServer.listen(0, '127.0.0.1', () => {
        const addr = smtpServer.server.address() as AddressInfo | null;
        if (!addr) reject(new Error('No SMTP port'));
        else resolve(addr.port);
      });
    });

    // Signup + login + create custom account inbox
    await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { email: 'owner@example.com', password: 'owner strong passphrase' },
    });
    const login = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'owner@example.com', password: 'owner strong passphrase' },
    });
    const cookie = extractCookieHeader(login.headers['set-cookie']);

    const created = await app.inject({
      method: 'POST',
      url: '/api/v1/account/inboxes',
      headers: { cookie, 'x-requested-with': 'XMLHttpRequest' },
      payload: { customName: 'vip-box', ttlMinutes: 60 },
    });
    expect(created.statusCode).toBe(201);
    const { id: inboxId, address } = created.json() as { id: string; address: string };

    // Send real SMTP email to account address
    const smtpRes = await sendSmtpCommandSequence(
      smtpPort,
      'alerts@service.com',
      address,
      'From: Alerts <alerts@service.com>\r\nSubject: Account OTP\r\n\r\nYour code is 774411.',
    );
    expect(smtpRes.startsWith('221')).toBe(true);

    // Read back via account messages API
    const msgsRes = await app.inject({
      method: 'GET',
      url: `/api/v1/account/inboxes/${inboxId}/messages`,
      headers: { cookie },
    });
    expect(msgsRes.statusCode).toBe(200);
    const msgs = (msgsRes.json() as { messages: Array<{ id: string; hasOtp: boolean }> }).messages;
    expect(msgs).toHaveLength(1);
    expect(msgs[0]?.hasOtp).toBe(true);

    // Expire the account inbox & clear Redis cache -> SMTP must reject with 550
    const rec = inboxes.get(inboxId);
    if (rec) {
      inboxes.set(inboxId, { ...rec, expiresAt: new Date(Date.now() - 1000) });
    }
    await redis.del(`acct:inbox:${address}`);

    const expiredSmtpRes = await sendSmtpCommandSequence(
      smtpPort,
      'alerts@service.com',
      address,
      'Subject: Late\r\n\r\nBody',
    );
    expect(expiredSmtpRes).toContain('550');
  });
});
