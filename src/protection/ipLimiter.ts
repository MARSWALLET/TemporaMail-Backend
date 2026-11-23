import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { redisKeys } from '../storage/redis.js';

export interface IpLimiterOptions {
  readonly maxSmtpMessagesPerMin: number;
  readonly smtpBanThresholdStrikes?: number;
  readonly banDurationSeconds?: number;
  readonly inboxAbuseThresholdPerHour?: number;
}

const DEFAULT_BAN_SECONDS = 3600;
const DEFAULT_STRIKES_BEFORE_BAN = 3;

export async function banIp(
  redis: Redis,
  ip: string,
  reason: string,
  durationSeconds: number = DEFAULT_BAN_SECONDS,
): Promise<void> {
  await redis.set(redisKeys.banIp(ip), reason, 'EX', durationSeconds);
}

/**
 * Checks per-IP SMTP message rate using `rl:smtp:{ip}` (1-minute window).
 * Repeat offenders hitting the limit multiple times receive `ban:ip:{ip}` for 1 hour.
 * Returns a rejection reason string if blocked, or null if allowed.
 */
export async function checkSmtpIpRateLimit(
  redis: Redis,
  ip: string,
  options: IpLimiterOptions,
  logger: Logger,
): Promise<string | null> {
  const key = redisKeys.rlSmtp(ip);
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, 60);
  }

  if (count <= options.maxSmtpMessagesPerMin) {
    return null;
  }

  const strikesKey = `rl:smtp:strikes:${ip}`;
  const strikes = await redis.incr(strikesKey);
  if (strikes === 1) {
    await redis.expire(strikesKey, 900); // 15-minute strike window
  }

  const threshold = options.smtpBanThresholdStrikes ?? DEFAULT_STRIKES_BEFORE_BAN;
  const banDuration = options.banDurationSeconds ?? DEFAULT_BAN_SECONDS;

  if (strikes >= threshold) {
    await banIp(redis, ip, 'smtp_rate_abuse', banDuration);
    logger.warn(
      { ip, count, strikes, banDuration, reason: 'smtp_repeat_rate_abuse_banned' },
      'IP auto-banned for repeated SMTP rate limit violations',
    );
    return 'smtp_repeat_rate_abuse_banned';
  }

  logger.warn(
    { ip, count, strikes, max: options.maxSmtpMessagesPerMin, reason: 'smtp_rate_limit_exceeded' },
    'SMTP per-IP rate limit exceeded',
  );
  return 'smtp_rate_limit_exceeded';
}

/**
 * Tracks excessive inbox creation attempts per IP and auto-bans abusive IPs.
 */
export async function recordInboxCreationAttempt(
  redis: Redis,
  ip: string,
  maxPerHour: number,
  logger: Logger,
  banDurationSeconds: number = DEFAULT_BAN_SECONDS,
): Promise<{ allowed: boolean; banned: boolean }> {
  const abuseKey = `rl:gen:abuse:${ip}`;
  const count = await redis.incr(abuseKey);
  if (count === 1) {
    await redis.expire(abuseKey, 3600);
  }

  // Ban if IP exceeds 3x the hourly inbox creation limit (minimum 20 attempts)
  const banThreshold = Math.max(maxPerHour * 3, 20);
  if (count > banThreshold) {
    await banIp(redis, ip, 'inbox_creation_abuse', banDurationSeconds);
    logger.warn(
      { ip, count, banThreshold, reason: 'inbox_creation_abuse_banned' },
      'IP auto-banned for excessive inbox creation attempts',
    );
    return { allowed: false, banned: true };
  }

  return { allowed: count <= maxPerHour, banned: false };
}
