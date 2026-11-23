import { Redis, type RedisOptions } from 'ioredis';
import {
  formatEmailAddress,
  generateLocalPart,
  generateOwnerToken,
  hashOwnerToken,
  normalizeAddress,
} from '../utils/address.js';

export const redisKeys = {
  inbox: (address: string): string => `inbox:${normalizeAddress(address)}`,
  inboxMsgs: (address: string): string => `inbox:${normalizeAddress(address)}:msgs`,
  msg: (id: string): string => `msg:${id}`,
  att: (id: string, index: number): string => `att:${id}:${index}`,
  rlGen: (ip: string): string => `rl:gen:${ip}`,
  rlApi: (ip: string): string => `rl:api:${ip}`,
  rlSmtp: (ip: string): string => `rl:smtp:${ip}`,
  banIp: (ip: string): string => `ban:ip:${ip}`,
  newChannel: (address: string): string => `new:${normalizeAddress(address)}`,
} as const;

export interface InboxRecord {
  readonly address: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly ownerTokenHash: string;
  readonly ip: string;
}

export interface CreateInboxInput {
  readonly domain: string;
  readonly ttlSeconds: number;
  readonly ip: string;
  readonly maxCollisionRetries?: number;
}

export interface CreateInboxResult {
  readonly address: string;
  readonly ownerToken: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

interface StoredMessageAttachmentShape {
  readonly attachments?: readonly unknown[];
}

export function createRedisClient(redisUrl: string, options: RedisOptions = {}): Redis {
  return new Redis(redisUrl, {
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    ...options,
  });
}

export async function inboxExists(redis: Redis, address: string): Promise<boolean> {
  const exists = await redis.exists(redisKeys.inbox(address));
  return exists === 1;
}

export async function isIpBanned(redis: Redis, ip: string): Promise<boolean> {
  const exists = await redis.exists(redisKeys.banIp(ip));
  return exists === 1;
}

export async function getInbox(redis: Redis, address: string): Promise<InboxRecord | null> {
  const normalized = normalizeAddress(address);
  const data = await redis.hgetall(redisKeys.inbox(normalized));

  if (!data.createdAt || !data.expiresAt || !data.ownerToken || !data.ip) {
    return null;
  }

  return {
    address: normalized,
    createdAt: Number(data.createdAt),
    expiresAt: Number(data.expiresAt),
    ownerTokenHash: data.ownerToken,
    ip: data.ip,
  };
}

export async function createInbox(
  redis: Redis,
  input: CreateInboxInput,
): Promise<CreateInboxResult> {
  const maxRetries = input.maxCollisionRetries ?? 10;

  for (let attempt = 0; attempt < maxRetries; attempt += 1) {
    const localPart = generateLocalPart();
    const address = formatEmailAddress(localPart, input.domain);
    const key = redisKeys.inbox(address);

    const alreadyExists = await redis.exists(key);
    if (alreadyExists === 1) {
      continue;
    }

    const ownerToken = generateOwnerToken();
    const ownerTokenHash = hashOwnerToken(ownerToken);
    const createdAt = Date.now();
    const expiresAt = createdAt + input.ttlSeconds * 1000;

    const pipeline = redis.pipeline();
    pipeline.hset(key, {
      createdAt: String(createdAt),
      expiresAt: String(expiresAt),
      ownerToken: ownerTokenHash,
      ip: input.ip,
    });
    pipeline.expire(key, input.ttlSeconds);
    await pipeline.exec();

    return {
      address,
      ownerToken,
      createdAt,
      expiresAt,
    };
  }

  throw new Error('Failed to generate a unique inbox address after maximum retries');
}

/**
 * Updates TTL across every Redis key belonging to an inbox:
 * - inbox:{address}
 * - inbox:{address}:msgs
 * - msg:{id}
 * - att:{id}:{index}
 */
export async function setInboxTTL(
  redis: Redis,
  address: string,
  seconds: number,
): Promise<{ updated: boolean; expiresAt: number }> {
  const normalized = normalizeAddress(address);
  const inboxKey = redisKeys.inbox(normalized);
  const exists = await redis.exists(inboxKey);

  if (exists !== 1) {
    return { updated: false, expiresAt: 0 };
  }

  const ttlSeconds = Math.max(1, Math.floor(seconds));
  const expiresAt = Date.now() + ttlSeconds * 1000;
  const msgsKey = redisKeys.inboxMsgs(normalized);
  const messageIds = await redis.lrange(msgsKey, 0, -1);

  const attachmentKeys: string[] = [];
  if (messageIds.length > 0) {
    const msgKeys = messageIds.map((id) => redisKeys.msg(id));
    const rawMessages = await redis.mget(...msgKeys);

    for (let i = 0; i < messageIds.length; i += 1) {
      const msgId = messageIds[i];
      const raw = rawMessages[i];
      if (!msgId || !raw) {
        continue;
      }

      try {
        const parsed = JSON.parse(raw) as StoredMessageAttachmentShape;
        const count = Array.isArray(parsed.attachments) ? parsed.attachments.length : 0;
        for (let idx = 0; idx < count; idx += 1) {
          attachmentKeys.push(redisKeys.att(msgId, idx));
        }
      } catch {
        // Ignore malformed message JSON when scanning attachment counts
      }
    }
  }

  const pipeline = redis.pipeline();
  pipeline.hset(inboxKey, 'expiresAt', String(expiresAt));
  pipeline.expire(inboxKey, ttlSeconds);
  pipeline.expire(msgsKey, ttlSeconds);

  for (const id of messageIds) {
    pipeline.expire(redisKeys.msg(id), ttlSeconds);
  }

  for (const attKey of attachmentKeys) {
    pipeline.expire(attKey, ttlSeconds);
  }

  await pipeline.exec();

  return { updated: true, expiresAt };
}

export async function deleteInbox(redis: Redis, address: string): Promise<boolean> {
  const normalized = normalizeAddress(address);
  const inboxKey = redisKeys.inbox(normalized);
  const exists = await redis.exists(inboxKey);

  if (exists !== 1) {
    return false;
  }

  const msgsKey = redisKeys.inboxMsgs(normalized);
  const messageIds = await redis.lrange(msgsKey, 0, -1);
  const keysToDelete: string[] = [inboxKey, msgsKey];

  if (messageIds.length > 0) {
    const msgKeys = messageIds.map((id) => redisKeys.msg(id));
    const rawMessages = await redis.mget(...msgKeys);

    for (let i = 0; i < messageIds.length; i += 1) {
      const msgId = messageIds[i];
      const raw = rawMessages[i];
      if (!msgId) {
        continue;
      }
      keysToDelete.push(redisKeys.msg(msgId));

      if (!raw) {
        continue;
      }

      try {
        const parsed = JSON.parse(raw) as StoredMessageAttachmentShape;
        const count = Array.isArray(parsed.attachments) ? parsed.attachments.length : 0;
        for (let idx = 0; idx < count; idx += 1) {
          keysToDelete.push(redisKeys.att(msgId, idx));
        }
      } catch {
        // Ignore malformed message JSON
      }
    }
  }

  await redis.del(...keysToDelete);
  return true;
}
