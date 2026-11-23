import { afterEach, describe, expect, it, vi } from 'vitest';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { loadEnv } from '../src/config/env.js';
import { BLOCKED_ATTACHMENT_EXTENSIONS, isBlockedExtension } from '../src/pipeline/attachments.js';
import { processIncomingMessage } from '../src/pipeline/processMessage.js';
import { sanitizeEmailHtml } from '../src/pipeline/sanitizer.js';
import type { StoredMessage } from '../src/pipeline/types.js';
import { createInbox, redisKeys } from '../src/storage/redis.js';
import { createLogger } from '../src/utils/logger.js';
import { extractOtpAndLinks } from '../src/utils/otp.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

describe('Step 2: HTML sanitization', () => {
  it('strips scripts, iframes, forms, event handlers, and javascript URLs', () => {
    const dirty = [
      '<div onclick="alert(1)">Hello</div>',
      '<script>evil()</script>',
      '<iframe src="https://evil.test/frame"></iframe>',
      '<form action="https://phish.test"><input name="pw" /></form>',
      '<a href="javascript:alert(2)">Click</a>',
      '<a href="https://example.com/verify?t=abc">Verify</a>',
    ].join('');

    const result = sanitizeEmailHtml(dirty);
    expect(result.html).not.toContain('<script');
    expect(result.html).not.toContain('evil()');
    expect(result.html).not.toContain('<iframe');
    expect(result.html).not.toContain('<form');
    expect(result.html).not.toContain('onclick');
    expect(result.html).not.toContain('javascript:');
    expect(result.html).toContain('https://example.com/verify?t=abc');
    expect(result.html).toContain('rel="noopener noreferrer nofollow"');
    expect(result.hasRemoteContent).toBe(true);
  });

  it('strips remote image sources and marks hasRemoteContent=true', () => {
    const html = '<p>Hi</p><img src="https://tracker.example.com/pixel.png" alt="Logo" width="1" />';
    const result = sanitizeEmailHtml(html);

    expect(result.hasRemoteContent).toBe(true);
    expect(result.html).not.toContain('tracker.example.com');
    expect(result.html).toContain('alt="Logo"');
  });

  it('keeps hasRemoteContent=false for local safe markup', () => {
    const html = '<p>Welcome to <strong>TemporaMail</strong></p>';
    const result = sanitizeEmailHtml(html);

    expect(result.hasRemoteContent).toBe(false);
    expect(result.html).toBe('<p>Welcome to <strong>TemporaMail</strong></p>');
  });
});

describe('Step 2: OTP and verification link detection', () => {
  it('extracts OTP when keyword precedes the digits', () => {
    const result = extractOtpAndLinks(
      'Your verification code',
      'Use verification code: 482910 to sign in. Expires in 10 minutes.',
      null,
    );
    expect(result.otp).toBe('482910');
  });

  it('extracts OTP when digits precede the keyword', () => {
    const result = extractOtpAndLinks(
      '739204 is your login code',
      'Enter this code in your browser.',
      null,
    );
    expect(result.otp).toBe('739204');
  });

  it('extracts verification links from plain text and HTML anchors', () => {
    const text = 'Visit https://app.example.com/verify?token=xyz123 to finish signup.';
    const html =
      '<p><a href="https://app.example.com/magic?id=99">Confirm your email</a></p><p><a href="https://app.example.com/privacy">Privacy</a></p>';

    const result = extractOtpAndLinks('Confirm account', text, html);
    expect(result.links).toContain('https://app.example.com/verify?token=xyz123');
    expect(result.links).toContain('https://app.example.com/magic?id=99');
    expect(result.links).not.toContain('https://app.example.com/privacy');
  });
});

describe('Step 2: Attachment extension blocking', () => {
  it('blocks all dangerous executable/script extensions including double extensions', () => {
    for (const ext of BLOCKED_ATTACHMENT_EXTENSIONS) {
      expect(isBlockedExtension(`malware${ext}`)).toBe(true);
      expect(isBlockedExtension(`INVOICE.PDF${ext.toUpperCase()}`)).toBe(true);
    }
    expect(isBlockedExtension('receipt.pdf')).toBe(false);
    expect(isBlockedExtension('photo.png')).toBe(false);
  });
});

describe('Step 2: Full message pipeline and Redis storage', () => {
  afterEach(async () => {
    const redis = createMockRedis();
    await redis.flushall();
  });

  it('parses MIME, sanitizes HTML, extracts OTP/links, filters attachments, stores in Redis, and publishes', async () => {
    const redis = createMockRedis();
    const config = loadEnv({
      NODE_ENV: 'test',
      MAX_MESSAGES_PER_INBOX: '2',
      MAX_MESSAGE_BYTES: '1048576',
    });
    const logger = createLogger('pipeline-test', 'silent', 'test');

    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });

    const publishSpy = vi.spyOn(redis, 'publish');

    const boundary = '----TemporaBoundary123';
    const rawMime = [
      'From: Security <security@example.com>',
      `To: ${inbox.address}`,
      'Subject: Verify your account',
      'MIME-Version: 1.0',
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Your OTP code is 918273. Confirm at https://example.com/verify?token=abc',
      `--${boundary}`,
      'Content-Type: text/html; charset="utf-8"',
      '',
      '<p>Your OTP code is <b>918273</b></p><script>alert(1)</script><img src="https://evil.test/px.gif" />',
      `--${boundary}`,
      'Content-Type: text/plain; name="notes.txt"',
      'Content-Disposition: attachment; filename="notes.txt"',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('Hello attachment!').toString('base64'),
      `--${boundary}`,
      'Content-Type: application/octet-stream; name="payload.exe"',
      'Content-Disposition: attachment; filename="payload.exe"',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('MZ-fake-exe').toString('base64'),
      `--${boundary}--`,
      '',
    ].join('\r\n');

    const result = await processIncomingMessage(
      {
        sessionId: 'sess-1',
        remoteAddress: '198.51.100.5',
        mailFrom: 'security@example.com',
        rcptTo: [inbox.address],
        raw: Buffer.from(rawMime, 'utf8'),
        receivedAt: new Date(),
      },
      { config, redis, logger },
    );

    const msgId = result.deliveredMessageIds.get(inbox.address);
    expect(msgId).toBeDefined();
    if (!msgId) {
      throw new Error('Expected msgId');
    }

    const storedRaw = await redis.get(redisKeys.msg(msgId));
    expect(storedRaw).not.toBeNull();
    const stored = JSON.parse(storedRaw ?? '{}') as StoredMessage;

    expect(stored.subject).toBe('Verify your account');
    expect(stored.otp).toBe('918273');
    expect(stored.links).toContain('https://example.com/verify?token=abc');
    expect(stored.html).not.toContain('<script');
    expect(stored.hasRemoteContent).toBe(true);
    expect(stored.attachments).toHaveLength(1);
    expect(stored.attachments[0]?.filename).toBe('notes.txt');

    const storedAtt = await redis.getBuffer(redisKeys.att(msgId, 0));
    expect(storedAtt?.toString('utf8')).toBe('Hello attachment!');
    expect(await redis.exists(redisKeys.att(msgId, 1))).toBe(0);

    const list = await redis.lrange(redisKeys.inboxMsgs(inbox.address), 0, -1);
    expect(list).toEqual([msgId]);
    expect(publishSpy).toHaveBeenCalledWith(redisKeys.newChannel(inbox.address), msgId);
  });

  it('trims inbox messages to MAX_MESSAGES_PER_INBOX and deletes evicted message keys', async () => {
    const redis = createMockRedis();
    const config = loadEnv({
      NODE_ENV: 'test',
      MAX_MESSAGES_PER_INBOX: '2',
    });
    const logger = createLogger('pipeline-test', 'silent', 'test');

    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });

    const ids: string[] = [];
    for (let i = 1; i <= 3; i += 1) {
      const res = await processIncomingMessage(
        {
          sessionId: `sess-${i}`,
          remoteAddress: '198.51.100.5',
          mailFrom: 'sender@example.com',
          rcptTo: [inbox.address],
          raw: Buffer.from(`From: sender@example.com\r\nSubject: Msg ${i}\r\n\r\nBody ${i}`),
          receivedAt: new Date(),
        },
        { config, redis, logger },
      );
      const id = res.deliveredMessageIds.get(inbox.address);
      if (id) {
        ids.push(id);
      }
    }

    const list = await redis.lrange(redisKeys.inboxMsgs(inbox.address), 0, -1);
    expect(list).toHaveLength(2);
    expect(list).toEqual([ids[2], ids[1]]);
    // Oldest message (ids[0]) should be evicted and deleted from Redis
    expect(await redis.exists(redisKeys.msg(ids[0] ?? ''))).toBe(0);
    expect(await redis.exists(redisKeys.msg(ids[2] ?? ''))).toBe(1);
  });

  it('rejects message with 554 when spamChecker returns reject', async () => {
    const redis = createMockRedis();
    const config = loadEnv({ NODE_ENV: 'test' });
    const logger = createLogger('pipeline-test', 'silent', 'test');

    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });

    await expect(
      processIncomingMessage(
        {
          sessionId: 'sess-spam',
          remoteAddress: '198.51.100.9',
          mailFrom: 'spammer@bad.test',
          rcptTo: [inbox.address],
          raw: Buffer.from('From: spammer@bad.test\r\nSubject: Buy now\r\n\r\nSpam body'),
          receivedAt: new Date(),
        },
        {
          config,
          redis,
          logger,
          spamChecker: async () => ({ action: 'reject', score: 18.5, reason: 'rspamd_high_score' }),
        },
      ),
    ).rejects.toMatchObject({ responseCode: 554 });

    expect(await redis.llen(redisKeys.inboxMsgs(inbox.address))).toBe(0);
  });
});
