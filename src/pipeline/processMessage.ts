import { randomUUID } from 'node:crypto';
import { simpleParser, type AddressObject } from 'mailparser';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import type { EnvConfig } from '../config/env.js';
import type { IncomingSmtpMessage, SmtpError } from '../smtp/server.js';
import { redisKeys } from '../storage/redis.js';
import { normalizeAddress } from '../utils/address.js';
import { extractOtpAndLinks } from '../utils/otp.js';
import { filterAttachments } from './attachments.js';
import { sanitizeEmailHtml } from './sanitizer.js';
import type { SpamChecker, StoredMessage } from './types.js';

export interface PipelineDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  readonly spamChecker?: SpamChecker;
}

export interface ProcessMessageResult {
  readonly deliveredMessageIds: ReadonlyMap<string, string>;
  readonly spamScore: number;
  readonly spamFlagged: boolean;
}

function createRejectError(message: string, responseCode: number): SmtpError {
  const err: SmtpError = new Error(message);
  err.responseCode = responseCode;
  return err;
}

function formatAddressObject(addr: AddressObject | AddressObject[] | undefined, fallback: string): string {
  if (!addr) {
    return fallback;
  }
  if (Array.isArray(addr)) {
    const first = addr[0];
    return first?.text || fallback;
  }
  return addr.text || fallback;
}

async function cleanupEvictedMessages(redis: Redis, evictedIds: readonly string[]): Promise<void> {
  if (evictedIds.length === 0) {
    return;
  }

  const msgKeys = evictedIds.map((id) => redisKeys.msg(id));
  const rawMessages = await redis.mget(...msgKeys);
  const keysToDelete: string[] = [...msgKeys];

  for (let i = 0; i < evictedIds.length; i += 1) {
    const msgId = evictedIds[i];
    const raw = rawMessages[i];
    if (!msgId || !raw) {
      continue;
    }

    try {
      const parsed = JSON.parse(raw) as { attachments?: readonly unknown[] };
      const count = Array.isArray(parsed.attachments) ? parsed.attachments.length : 0;
      for (let idx = 0; idx < count; idx += 1) {
        keysToDelete.push(redisKeys.att(msgId, idx));
      }
    } catch {
      // Ignore malformed JSON
    }
  }

  await redis.del(...keysToDelete);
}

export async function processIncomingMessage(
  message: IncomingSmtpMessage,
  deps: PipelineDependencies,
): Promise<ProcessMessageResult> {
  const { config, redis, logger, spamChecker } = deps;

  // 1. Parse raw MIME message
  const parsed = await simpleParser(message.raw);
  const subject = parsed.subject?.trim() ?? '';
  const text = parsed.text?.trim() ?? '';
  const rawHtml = typeof parsed.html === 'string' ? parsed.html : '';

  // 2. Run spam checks (Step 5 hook)
  let spamScore = 0;
  let spamFlagged = false;

  if (spamChecker) {
    const spamResult = await spamChecker({
      raw: message.raw,
      remoteAddress: message.remoteAddress,
      mailFrom: message.mailFrom,
      rcptTo: message.rcptTo,
      subject,
      text,
    });

    spamScore = spamResult.score;
    if (spamResult.action === 'reject') {
      logger.warn(
        {
          sessionId: message.sessionId,
          ip: message.remoteAddress,
          mailFrom: message.mailFrom,
          rcptTo: message.rcptTo,
          spamScore,
          reason: spamResult.reason ?? 'spam_rejected',
        },
        'Message rejected by spam checks',
      );
      throw createRejectError('5.7.1 Message rejected as spam', 554);
    }
    spamFlagged = spamResult.action === 'flag';
  }

  // 3. Sanitize HTML and detect remote content
  const sanitized = sanitizeEmailHtml(rawHtml);

  // 4. Detect OTP codes and verification links
  const { otp, links } = extractOtpAndLinks(subject, text, rawHtml || null);

  // 5. Filter attachments (block dangerous extensions & enforce total size limit)
  const { accepted: attachments, rejected: rejectedAttachments } = filterAttachments(
    parsed.attachments ?? [],
    config.maxMessageBytes,
  );

  if (rejectedAttachments.length > 0) {
    logger.warn(
      {
        sessionId: message.sessionId,
        mailFrom: message.mailFrom,
        rejectedAttachments,
      },
      'Blocked or skipped message attachments',
    );
  }

  const from = formatAddressObject(parsed.from, message.mailFrom);
  const date = (parsed.date ?? message.receivedAt).toISOString();
  const deliveredMessageIds = new Map<string, string>();

  // 6 & 7. Store per-recipient message, attachments, trim inbox list, and publish event
  for (const rawRecipient of message.rcptTo) {
    const recipient = normalizeAddress(rawRecipient);
    const inboxKey = redisKeys.inbox(recipient);
    const remainingTtl = await redis.ttl(inboxKey);

    if (remainingTtl <= 0) {
      logger.info(
        { sessionId: message.sessionId, recipient },
        'Skipping delivery to expired or missing inbox',
      );
      continue;
    }

    const msgId = randomUUID();
    const storedMessage: StoredMessage = {
      id: msgId,
      from,
      to: [recipient],
      subject,
      date,
      text,
      html: sanitized.html,
      hasRemoteContent: sanitized.hasRemoteContent,
      otp,
      links,
      attachments: attachments.map((a) => a.metadata),
      spamScore,
      spamFlagged,
    };

    const msgsKey = redisKeys.inboxMsgs(recipient);
    const pipeline = redis.pipeline();
    pipeline.set(redisKeys.msg(msgId), JSON.stringify(storedMessage), 'EX', remainingTtl);

    for (const att of attachments) {
      pipeline.set(redisKeys.att(msgId, att.metadata.index), att.content, 'EX', remainingTtl);
    }

    pipeline.lpush(msgsKey, msgId);
    pipeline.expire(msgsKey, remainingTtl);
    await pipeline.exec();

    // Trim inbox to MAX_MESSAGES_PER_INBOX and delete evicted keys
    const evictedIds = await redis.lrange(msgsKey, config.maxMessagesPerInbox, -1);
    if (evictedIds.length > 0) {
      await redis.ltrim(msgsKey, 0, config.maxMessagesPerInbox - 1);
      await cleanupEvictedMessages(redis, evictedIds);
    }

    // Publish new message ID for SSE subscribers
    await redis.publish(redisKeys.newChannel(recipient), msgId);
    deliveredMessageIds.set(recipient, msgId);

    logger.info(
      {
        sessionId: message.sessionId,
        recipient,
        msgId,
        hasOtp: otp !== null,
        linksCount: links.length,
        attachmentsCount: attachments.length,
        spamScore,
        spamFlagged,
      },
      'Stored inbound message and published notification',
    );
  }

  return {
    deliveredMessageIds,
    spamScore,
    spamFlagged,
  };
}
