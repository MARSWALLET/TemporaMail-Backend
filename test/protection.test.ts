import { afterEach, describe, expect, it, vi } from 'vitest';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import { BlocklistStore } from '../src/protection/blocklist.js';
import { checkDnsbl, isPrivateOrLoopbackIp, reverseIpv4 } from '../src/protection/dnsbl.js';
import { checkSmtpIpRateLimit, recordInboxCreationAttempt } from '../src/protection/ipLimiter.js';
import { verifyMailAuth } from '../src/protection/mailAuth.js';
import { checkRspamd } from '../src/protection/rspamd.js';
import { createCompositeSpamChecker } from '../src/protection/spamChecker.js';
import { verifyTurnstileToken } from '../src/protection/turnstile.js';
import { isIpBanned } from '../src/storage/redis.js';
import { createLogger } from '../src/utils/logger.js';

function createMockRedis(): Redis {
  return new RedisMock() as unknown as Redis;
}

const logger = createLogger('protection-test', 'silent', 'test');

describe('Step 5: Protection Layer', () => {
  afterEach(async () => {
    const cleanup = createMockRedis();
    await cleanup.flushall();
  });

  describe('IP rate limits & auto-ban', () => {
    it('rate-limits SMTP messages per minute and auto-bans repeat offenders', async () => {
      const redis = createMockRedis();
      const ip = '198.51.100.42';
      const opts = { maxSmtpMessagesPerMin: 2, smtpBanThresholdStrikes: 2, banDurationSeconds: 3600 };

      expect(await checkSmtpIpRateLimit(redis, ip, opts, logger)).toBeNull();
      expect(await checkSmtpIpRateLimit(redis, ip, opts, logger)).toBeNull();
      expect(await checkSmtpIpRateLimit(redis, ip, opts, logger)).toBe('smtp_rate_limit_exceeded');
      expect(await isIpBanned(redis, ip)).toBe(false);

      // Second strike triggers 1-hour ban
      expect(await checkSmtpIpRateLimit(redis, ip, opts, logger)).toBe(
        'smtp_repeat_rate_abuse_banned',
      );
      expect(await isIpBanned(redis, ip)).toBe(true);
    });

    it('auto-bans IPs abusing inbox creation beyond threshold', async () => {
      const redis = createMockRedis();
      const ip = '203.0.113.77';

      for (let i = 0; i < 20; i += 1) {
        await recordInboxCreationAttempt(redis, ip, 5, logger);
      }
      const over = await recordInboxCreationAttempt(redis, ip, 5, logger);
      expect(over.banned).toBe(true);
      expect(await isIpBanned(redis, ip)).toBe(true);
    });
  });

  describe('DNSBL', () => {
    it('skips private/loopback IPs and reverses public IPv4 octets', () => {
      expect(isPrivateOrLoopbackIp('127.0.0.1')).toBe(true);
      expect(isPrivateOrLoopbackIp('10.1.2.3')).toBe(true);
      expect(isPrivateOrLoopbackIp('192.168.0.1')).toBe(true);
      expect(isPrivateOrLoopbackIp('172.16.5.1')).toBe(true);
      expect(isPrivateOrLoopbackIp('198.51.100.9')).toBe(false);
      expect(reverseIpv4('1.2.3.4')).toBe('4.3.2.1');
    });

    it('rejects listed IP and caches the DNSBL result in Redis', async () => {
      const redis = createMockRedis();
      const resolve4 = vi.fn(async (host: string) => {
        if (host === '9.100.51.198.zen.spamhaus.org') {
          return ['127.0.0.2'];
        }
        const err = new Error('NXDOMAIN') as NodeJS.ErrnoException;
        err.code = 'ENOTFOUND';
        throw err;
      });

      const first = await checkDnsbl(
        redis,
        '198.51.100.9',
        { resolverIp: '127.0.0.1', zones: ['zen.spamhaus.org'], resolve4 },
        logger,
      );
      expect(first).toBe('dnsbl:zen.spamhaus.org');
      expect(resolve4).toHaveBeenCalledTimes(1);

      // Second call uses Redis cache
      const second = await checkDnsbl(
        redis,
        '198.51.100.9',
        { resolverIp: '127.0.0.1', zones: ['zen.spamhaus.org'], resolve4 },
        logger,
      );
      expect(second).toBe('dnsbl:zen.spamhaus.org');
      expect(resolve4).toHaveBeenCalledTimes(1);
    });

    it('fails open when DNS lookup throws a transient error', async () => {
      const redis = createMockRedis();
      const resolve4 = vi.fn(async () => {
        const err = new Error('SERVFAIL') as NodeJS.ErrnoException;
        err.code = 'ESERVFAIL';
        throw err;
      });

      const result = await checkDnsbl(
        redis,
        '198.51.100.12',
        { resolverIp: '127.0.0.1', zones: ['zen.spamhaus.org'], resolve4 },
        logger,
      );
      expect(result).toBeNull();
    });
  });

  describe('SPF / DKIM / DMARC (mailauth)', () => {
    it('rejects hard DMARC failure when policy is reject', async () => {
      const outcome = await verifyMailAuth(
        { raw: Buffer.from('Subject: Test\r\n\r\nHi'), ip: '198.51.100.1', sender: 'a@bank.com' },
        logger,
        async () => ({
          spf: { status: { result: 'fail' } },
          dkim: { results: [{ status: { result: 'fail' } }] },
          dmarc: { status: { result: 'fail' }, policy: 'reject' },
        }),
      );

      expect(outcome.reject).toBe(true);
      expect(outcome.reason).toBe('dmarc_policy_reject');
    });

    it('adds spam score without rejecting when DMARC policy is quarantine', async () => {
      const outcome = await verifyMailAuth(
        { raw: Buffer.from('Subject: Test\r\n\r\nHi'), ip: '198.51.100.1', sender: 'a@example.com' },
        logger,
        async () => ({
          spf: { status: { result: 'fail' } },
          dkim: { results: [{ status: { result: 'pass' } }] },
          dmarc: { status: { result: 'fail' }, policy: 'quarantine' },
        }),
      );

      expect(outcome.reject).toBe(false);
      expect(outcome.scoreDelta).toBe(5);
    });

    it('fails open if mailauth throws', async () => {
      const outcome = await verifyMailAuth(
        { raw: Buffer.from('Subject: Test\r\n\r\nHi'), ip: '198.51.100.1', sender: 'a@example.com' },
        logger,
        async () => {
          throw new Error('DNS timeout');
        },
      );

      expect(outcome.reject).toBe(false);
      expect(outcome.scoreDelta).toBe(0);
    });
  });

  describe('Rspamd', () => {
    it('rejects above rejectScore, flags above flagScore, and fails open when down', async () => {
      const baseInput = {
        raw: Buffer.from('Subject: Hi\r\n\r\nBody'),
        ip: '198.51.100.5',
        mailFrom: 's@example.com',
        rcptTo: ['u@temporamail.app'],
      };

      const high = await checkRspamd(
        baseInput,
        {
          rspamdUrl: 'http://rspamd:11334',
          rejectScore: 15,
          flagScore: 6,
          fetchImpl: async () => new Response(JSON.stringify({ score: 17.2 }), { status: 200 }),
        },
        logger,
      );
      expect(high.action).toBe('reject');

      const mid = await checkRspamd(
        baseInput,
        {
          rspamdUrl: 'http://rspamd:11334',
          rejectScore: 15,
          flagScore: 6,
          fetchImpl: async () => new Response(JSON.stringify({ score: 8.5 }), { status: 200 }),
        },
        logger,
      );
      expect(mid.action).toBe('flag');

      const down = await checkRspamd(
        baseInput,
        {
          rspamdUrl: 'http://rspamd:11334',
          rejectScore: 15,
          flagScore: 6,
          fetchImpl: async () => {
            throw new Error('ECONNREFUSED');
          },
        },
        logger,
      );
      expect(down.available).toBe(false);
      expect(down.action).toBe('accept');
    });
  });

  describe('Blocklist, Turnstile & Composite Spam Checker', () => {
    it('matches IP, sender, domain, and keywords in BlocklistStore', () => {
      const store = new BlocklistStore([
        { type: 'ip', value: '203.0.113.5', reason: 'known_spammer' },
        { type: 'sender', value: 'evil@bad.test', reason: 'phishing_sender' },
        { type: 'domain', value: 'spamdomain.xyz', reason: 'spam_domain' },
        { type: 'keyword', value: 'buy cheap crypto now', reason: 'spam_keyword' },
      ]);

      expect(
        store.checkMessage({
          ip: '203.0.113.5',
          mailFrom: 'ok@good.com',
          subject: 'Hi',
          text: 'Hello',
        }),
      ).toMatchObject({ matched: true, type: 'ip', reason: 'known_spammer' });

      expect(
        store.checkMessage({
          ip: '198.51.100.1',
          mailFrom: 'user@spamdomain.xyz',
          subject: 'Hi',
          text: 'Hello',
        }),
      ).toMatchObject({ matched: true, type: 'domain', reason: 'spam_domain' });

      expect(
        store.checkMessage({
          ip: '198.51.100.1',
          mailFrom: 'ok@good.com',
          subject: 'Offer',
          text: 'Click here to BUY CHEAP CRYPTO NOW!',
        }),
      ).toMatchObject({ matched: true, type: 'keyword', reason: 'spam_keyword' });
    });

    it('verifies Cloudflare Turnstile tokens server-side', async () => {
      const ok = await verifyTurnstileToken(
        'good-token',
        '198.51.100.1',
        {
          secret: 'test-secret',
          fetchImpl: async () => new Response(JSON.stringify({ success: true }), { status: 200 }),
        },
        logger,
      );
      expect(ok).toBe(true);

      const bad = await verifyTurnstileToken(
        'bad-token',
        '198.51.100.1',
        {
          secret: 'test-secret',
          fetchImpl: async () =>
            new Response(JSON.stringify({ success: false, 'error-codes': ['invalid-input-response'] }), {
              status: 200,
            }),
        },
        logger,
      );
      expect(bad).toBe(false);
    });

    it('combines blocklist, mailauth, and rspamd in composite spam checker', async () => {
      const blocklist = new BlocklistStore([{ type: 'domain', value: 'blocked.test' }]);
      const checker = createCompositeSpamChecker({
        logger,
        blocklist,
        getThresholds: () => ({ rspamdUrl: 'http://rspamd:11334', rejectScore: 15, flagScore: 6 }),
        authenticateImpl: async () => ({
          spf: { status: { result: 'fail' } },
          dkim: { results: [] },
          dmarc: { status: { result: 'none' } },
        }),
        fetchImpl: async () => new Response(JSON.stringify({ score: 5 }), { status: 200 }),
      });

      // Blocked domain -> immediate reject
      const blocked = await checker({
        raw: Buffer.from('Subject: Hi\r\n\r\nBody'),
        remoteAddress: '198.51.100.1',
        mailFrom: 'x@blocked.test',
        rcptTo: ['u@temporamail.app'],
        subject: 'Hi',
        text: 'Body',
      });
      expect(blocked.action).toBe('reject');

      // SPF fail (+2) + Rspamd (+5) = 7 >= flagScore (6) -> flag
      const flagged = await checker({
        raw: Buffer.from('Subject: Hi\r\n\r\nBody'),
        remoteAddress: '198.51.100.1',
        mailFrom: 'x@allowed.test',
        rcptTo: ['u@temporamail.app'],
        subject: 'Hi',
        text: 'Body',
      });
      expect(flagged.action).toBe('flag');
      expect(flagged.score).toBe(7);
    });
  });
});
