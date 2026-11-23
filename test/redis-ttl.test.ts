import { describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import {
  createInbox,
  deleteInbox,
  getInbox,
  inboxExists,
  redisKeys,
  setInboxTTL,
} from '../src/storage/redis.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

describe('Redis inbox storage and setInboxTTL', () => {
  it('creates and retrieves an inbox with hashed ownerToken', async () => {
    const redis = createMockRedis();
    const created = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '203.0.113.10',
    });

    expect(created.address.endsWith('@temporamail.app')).toBe(true);
    expect(await inboxExists(redis, created.address)).toBe(true);

    const record = await getInbox(redis, created.address);
    expect(record).not.toBeNull();
    expect(record?.ip).toBe('203.0.113.10');
    expect(record?.ownerTokenHash).not.toBe(created.ownerToken);
  });

  it('extends TTL across inbox, msgs list, messages, and attachments together', async () => {
    const redis = createMockRedis();
    const created = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 120,
      ip: '203.0.113.10',
    });

    const msgId = 'msg-1';
    const msgsKey = redisKeys.inboxMsgs(created.address);
    const msgKey = redisKeys.msg(msgId);
    const att0Key = redisKeys.att(msgId, 0);
    const att1Key = redisKeys.att(msgId, 1);

    await redis.lpush(msgsKey, msgId);
    await redis.expire(msgsKey, 120);
    await redis.set(
      msgKey,
      JSON.stringify({ id: msgId, attachments: [{ filename: 'a.txt' }, { filename: 'b.txt' }] }),
      'EX',
      120,
    );
    await redis.set(att0Key, 'attachment-0', 'EX', 120);
    await redis.set(att1Key, 'attachment-1', 'EX', 120);

    const result = await setInboxTTL(redis, created.address, 1800);
    expect(result.updated).toBe(true);

    const inboxTtl = await redis.ttl(redisKeys.inbox(created.address));
    const msgsTtl = await redis.ttl(msgsKey);
    const msgTtl = await redis.ttl(msgKey);
    const att0Ttl = await redis.ttl(att0Key);
    const att1Ttl = await redis.ttl(att1Key);

    for (const ttl of [inboxTtl, msgsTtl, msgTtl, att0Ttl, att1Ttl]) {
      expect(ttl).toBeGreaterThan(1700);
      expect(ttl).toBeLessThanOrEqual(1800);
    }

    const updatedRecord = await getInbox(redis, created.address);
    expect(updatedRecord?.expiresAt).toBe(result.expiresAt);
  });

  it('returns updated=false when extending a nonexistent inbox', async () => {
    const redis = createMockRedis();
    const result = await setInboxTTL(redis, 'missing@temporamail.app', 600);
    expect(result.updated).toBe(false);
  });

  it('deletes inbox along with all messages and attachments', async () => {
    const redis = createMockRedis();
    const created = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 300,
      ip: '203.0.113.10',
    });

    const msgId = 'msg-del';
    await redis.lpush(redisKeys.inboxMsgs(created.address), msgId);
    await redis.set(
      redisKeys.msg(msgId),
      JSON.stringify({ id: msgId, attachments: [{ filename: 'x.pdf' }] }),
    );
    await redis.set(redisKeys.att(msgId, 0), 'pdf-bytes');

    const deleted = await deleteInbox(redis, created.address);
    expect(deleted).toBe(true);

    expect(await redis.exists(redisKeys.inbox(created.address))).toBe(0);
    expect(await redis.exists(redisKeys.inboxMsgs(created.address))).toBe(0);
    expect(await redis.exists(redisKeys.msg(msgId))).toBe(0);
    expect(await redis.exists(redisKeys.att(msgId, 0))).toBe(0);
  });
});
