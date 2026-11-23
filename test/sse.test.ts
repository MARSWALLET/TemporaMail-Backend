import http from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { createApiApp } from '../src/api/app.js';
import { loadEnv } from '../src/config/env.js';
import { processIncomingMessage } from '../src/pipeline/processMessage.js';
import { createInbox } from '../src/storage/redis.js';
import { InboxEventHub } from '../src/stream/pubsub.js';
import { createLogger } from '../src/utils/logger.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

describe('Step 4: Live Stream (SSE)', () => {
  const openApps: FastifyInstance[] = [];
  const openHubs: InboxEventHub[] = [];

  afterEach(async () => {
    while (openApps.length > 0) {
      const app = openApps.pop();
      if (app) {
        await app.close();
      }
    }
    while (openHubs.length > 0) {
      const hub = openHubs.pop();
      if (hub) {
        await hub.close();
      }
    }
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  async function startSseApp(heartbeatMs: number = 25_000) {
    const redis = createMockRedis();
    const subscriber = redis.duplicate();
    const config = loadEnv({ NODE_ENV: 'test' });
    const logger = createLogger('sse-test', 'silent', 'test');
    const eventHub = new InboxEventHub(subscriber, logger);
    await eventHub.start();
    openHubs.push(eventHub);

    const app = await createApiApp({
      config,
      redis,
      logger,
      eventHub,
      sseHeartbeatMs: heartbeatMs,
    });
    openApps.push(app);

    const baseUrl = await app.listen({ host: '127.0.0.1', port: 0 });
    return { app, redis, config, logger, eventHub, baseUrl };
  }

  it('returns 404 for a nonexistent inbox', async () => {
    const { app } = await startSseApp();
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/inbox/missing@temporamail.app/stream',
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('INBOX_NOT_FOUND');
  });

  it('delivers message summary event over SSE when mail arrives and cleans up on disconnect', async () => {
    const { redis, config, logger, eventHub, baseUrl } = await startSseApp(5000);
    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });

    const receivedChunks: string[] = [];

    await new Promise<void>((resolve, reject) => {
      const req = http.get(
        `${baseUrl}/api/v1/inbox/${encodeURIComponent(inbox.address)}/stream`,
        (res) => {
          expect(res.statusCode).toBe(200);
          expect(res.headers['content-type']).toContain('text/event-stream');

          let delivered = false;
          res.setEncoding('utf8');
          res.on('data', (chunk: string) => {
            receivedChunks.push(chunk);
            const joined = receivedChunks.join('');

            if (!delivered && joined.includes(': connected')) {
              delivered = true;
              expect(eventHub.getListenerCount(inbox.address)).toBe(1);

              void processIncomingMessage(
                {
                  sessionId: 'sse-sess-1',
                  remoteAddress: '198.51.100.1',
                  mailFrom: 'verify@service.test',
                  rcptTo: [inbox.address],
                  raw: Buffer.from(
                    [
                      'From: Service <verify@service.test>',
                      `To: ${inbox.address}`,
                      'Subject: Your login code',
                      '',
                      'Your verification code is 551199.',
                    ].join('\r\n'),
                  ),
                  receivedAt: new Date(),
                },
                { config, redis, logger },
              ).catch(reject);
            }

            if (joined.includes('event: message')) {
              req.destroy();
              resolve();
            }
          });
        },
      );
      req.on('error', (err) => {
        if ((err as NodeJS.ErrnoException).code !== 'ECONNRESET') {
          reject(err);
        }
      });
    });

    const fullStream = receivedChunks.join('');
    expect(fullStream).toContain('event: message');
    expect(fullStream).toContain('"subject":"Your login code"');
    expect(fullStream).toContain('"hasOtp":true');

    // Wait a tick for server socket close handler to fire
    await new Promise((r) => setTimeout(r, 50));
    expect(eventHub.getListenerCount(inbox.address)).toBe(0);
  });

  it('sends periodic heartbeat comments', async () => {
    const { redis, baseUrl } = await startSseApp(60);
    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });

    const chunks: string[] = [];
    await new Promise<void>((resolve, reject) => {
      const req = http.get(
        `${baseUrl}/api/v1/inbox/${encodeURIComponent(inbox.address)}/stream`,
        (res) => {
          res.setEncoding('utf8');
          res.on('data', (chunk: string) => {
            chunks.push(chunk);
            if (chunks.join('').includes(': heartbeat')) {
              req.destroy();
              resolve();
            }
          });
        },
      );
      req.on('error', (err) => {
        if ((err as NodeJS.ErrnoException).code !== 'ECONNRESET') {
          reject(err);
        }
      });
    });

    expect(chunks.join('')).toContain(': heartbeat');
  });

  it('sends event: expired and closes when the inbox expires', async () => {
    const { redis, eventHub, baseUrl } = await startSseApp(5000);
    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 1,
      ip: '127.0.0.1',
    });

    // Shorten expiresAt to 150ms from now so the test completes quickly
    await redis.hset(`inbox:${inbox.address}`, 'expiresAt', String(Date.now() + 150));

    const chunks: string[] = [];
    await new Promise<void>((resolve, reject) => {
      const req = http.get(
        `${baseUrl}/api/v1/inbox/${encodeURIComponent(inbox.address)}/stream`,
        (res) => {
          res.setEncoding('utf8');
          res.on('data', (chunk: string) => {
            chunks.push(chunk);
          });
          res.on('end', () => resolve());
        },
      );
      req.on('error', reject);
    });

    expect(chunks.join('')).toContain('event: expired');
    expect(eventHub.getListenerCount(inbox.address)).toBe(0);
  });
});
