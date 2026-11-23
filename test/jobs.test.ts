import { afterEach, describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { runDomainHealthCheck } from '../src/jobs/domainHealth.js';
import { runRedisCleanup } from '../src/jobs/redisCleanup.js';
import { createInbox, redisKeys } from '../src/storage/redis.js';
import { createLogger } from '../src/utils/logger.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

const logger = createLogger('jobs-test', 'silent', 'test');

describe('Step 8: Maintenance jobs', () => {
  afterEach(async () => {
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  it('removes orphaned inbox:*:msgs, msg:*, and att:* keys when parent inbox is gone', async () => {
    const redis = createMockRedis();
    const orphanAddr = 'gone@temporamail.app';
    const msgId = 'orphan-msg-1';

    await redis.lpush(redisKeys.inboxMsgs(orphanAddr), msgId);
    await redis.set(
      redisKeys.msg(msgId),
      JSON.stringify({ id: msgId, attachments: [{ filename: 'a.txt' }] }),
    );
    await redis.set(redisKeys.att(msgId, 0), 'attachment-bytes');

    const stats = await runRedisCleanup(redis, logger);
    expect(stats.orphansRemoved).toBe(3);
    expect(await redis.exists(redisKeys.inboxMsgs(orphanAddr))).toBe(0);
    expect(await redis.exists(redisKeys.msg(msgId))).toBe(0);
    expect(await redis.exists(redisKeys.att(msgId, 0))).toBe(0);
  });

  it('repairs missing TTLs on child keys to match active parent inbox TTL', async () => {
    const redis = createMockRedis();
    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 300,
      ip: '127.0.0.1',
    });

    const msgId = 'msg-no-ttl';
    const msgsKey = redisKeys.inboxMsgs(inbox.address);
    const msgKey = redisKeys.msg(msgId);
    const attKey = redisKeys.att(msgId, 0);

    // Intentionally omit EXPIRE on child keys
    await redis.lpush(msgsKey, msgId);
    await redis.set(msgKey, JSON.stringify({ id: msgId, attachments: [{ filename: 'x.txt' }] }));
    await redis.set(attKey, 'bytes');

    expect(await redis.ttl(msgKey)).toBe(-1);

    const stats = await runRedisCleanup(redis, logger);
    expect(stats.ttlsRepaired).toBe(3);

    for (const key of [msgsKey, msgKey, attKey]) {
      const ttl = await redis.ttl(key);
      expect(ttl).toBeGreaterThan(200);
      expect(ttl).toBeLessThanOrEqual(300);
    }
  });

  it('checks domain MX records and mail hostname DNS resolution', async () => {
    const report = await runDomainHealthCheck(
      {
        mailHostname: 'mail.temporamail.app',
        domains: ['temporamail.app', 'misconfigured.app'],
        resolveHost: async (host) => (host === 'mail.temporamail.app' ? ['203.0.113.10'] : []),
        resolveMx: async (domain) =>
          domain === 'temporamail.app'
            ? [{ exchange: 'mail.temporamail.app', priority: 10 }]
            : [{ exchange: 'other.mail.host', priority: 10 }],
      },
      logger,
    );

    expect(report.mailHostnameResolved).toBe(true);
    expect(report.domains).toEqual([
      { domain: 'temporamail.app', mxValid: true, mxRecords: ['mail.temporamail.app'] },
      { domain: 'misconfigured.app', mxValid: false, mxRecords: ['other.mail.host'] },
    ]);
    expect(report.tlsCertDaysRemaining).toBeNull();
  });
});
