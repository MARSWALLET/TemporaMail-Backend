import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { redisKeys } from '../storage/redis.js';

export interface RedisCleanupStats {
  readonly orphansRemoved: number;
  readonly ttlsRepaired: number;
}

interface MessageAttachmentCountShape {
  readonly attachments?: readonly unknown[];
}

async function scanKeys(redis: Redis, pattern: string): Promise<string[]> {
  const keys: string[] = [];
  let cursor = '0';

  do {
    const [nextCursor, batch] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 200);
    cursor = nextCursor;
    keys.push(...batch);
  } while (cursor !== '0');

  return keys;
}

async function collectAttachmentKeys(
  redis: Redis,
  messageIds: readonly string[],
): Promise<string[]> {
  if (messageIds.length === 0) {
    return [];
  }

  const rawMessages = await redis.mget(...messageIds.map((id) => redisKeys.msg(id)));
  const attKeys: string[] = [];

  for (let i = 0; i < messageIds.length; i += 1) {
    const msgId = messageIds[i];
    const raw = rawMessages[i];
    if (!msgId || !raw) {
      continue;
    }

    try {
      const parsed = JSON.parse(raw) as MessageAttachmentCountShape;
      const count = Array.isArray(parsed.attachments) ? parsed.attachments.length : 0;
      for (let idx = 0; idx < count; idx += 1) {
        attKeys.push(redisKeys.att(msgId, idx));
      }
    } catch {
      // Ignore malformed JSON
    }
  }

  return attKeys;
}

/**
 * 1. Deletes orphaned `inbox:{addr}:msgs` (and their messages/attachments) when `inbox:{addr}` no longer exists.
 * 2. Ensures every child key (`:msgs`, `msg:*`, `att:*`) of an active inbox has a TTL matching the inbox.
 */
export async function runRedisCleanup(redis: Redis, logger: Logger): Promise<RedisCleanupStats> {
  let orphansRemoved = 0;
  let ttlsRepaired = 0;

  const msgsListKeys = await scanKeys(redis, 'inbox:*:msgs');

  for (const msgsKey of msgsListKeys) {
    const inboxKey = msgsKey.slice(0, -':msgs'.length);
    const inboxTtl = await redis.ttl(inboxKey);
    const messageIds = await redis.lrange(msgsKey, 0, -1);

    if (inboxTtl === -2) {
      // Parent inbox is gone -> remove orphaned list, messages, and attachments
      const attKeys = await collectAttachmentKeys(redis, messageIds);
      const toDelete = [msgsKey, ...messageIds.map((id) => redisKeys.msg(id)), ...attKeys];
      if (toDelete.length > 0) {
        const deleted = await redis.del(...toDelete);
        orphansRemoved += deleted;
      }
      continue;
    }

    if (inboxTtl > 0) {
      // Repair any child keys missing TTL (-1) or outliving their parent inbox
      const attKeys = await collectAttachmentKeys(redis, messageIds);
      const childKeys = [msgsKey, ...messageIds.map((id) => redisKeys.msg(id)), ...attKeys];

      for (const childKey of childKeys) {
        const childTtl = await redis.ttl(childKey);
        if (childTtl === -1 || childTtl > inboxTtl + 5) {
          await redis.expire(childKey, inboxTtl);
          ttlsRepaired += 1;
        }
      }
    }
  }

  if (orphansRemoved > 0 || ttlsRepaired > 0) {
    logger.info({ orphansRemoved, ttlsRepaired }, 'Redis cleanup job completed');
  }

  return { orphansRemoved, ttlsRepaired };
}
