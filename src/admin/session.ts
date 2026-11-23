import { randomBytes } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import type { AdminRole } from './permissions.js';

export const ADMIN_SESSION_MAX_LIFETIME_MS = 8 * 60 * 60 * 1000; // 8 hours
export const ADMIN_SESSION_IDLE_TTL_SECONDS = 30 * 60; // 30 minutes idle timeout

export interface AdminSessionData {
  readonly sessionId: string;
  readonly adminUserId: string;
  readonly email: string;
  readonly role: AdminRole;
  readonly ip: string;
  readonly createdAt: number;
  readonly lastSeenAt: number;
}

/**
 * Completely separate cookie name and Redis key namespace from normal user sessions.
 * A normal user session can never authenticate against `/admin/api/v1`.
 */
export function getAdminSessionCookieName(nodeEnv: string): string {
  return nodeEnv === 'production' ? '__Host-tm_admin_session' : 'tm_admin_session';
}

export function adminSessionRedisKey(sessionId: string): string {
  return `sess:admin:${sessionId}`;
}

export function adminUserSessionsSetKey(adminUserId: string): string {
  return `admin:sessions:${adminUserId}`;
}

export async function createAdminSession(
  redis: Redis,
  input: {
    readonly adminUserId: string;
    readonly email: string;
    readonly role: AdminRole;
    readonly ip: string;
  },
): Promise<AdminSessionData> {
  const sessionId = randomBytes(32).toString('hex');
  const now = Date.now();

  const data: AdminSessionData = {
    sessionId,
    adminUserId: input.adminUserId,
    email: input.email,
    role: input.role,
    ip: input.ip,
    createdAt: now,
    lastSeenAt: now,
  };

  const pipeline = redis.pipeline();
  pipeline.set(
    adminSessionRedisKey(sessionId),
    JSON.stringify(data),
    'EX',
    ADMIN_SESSION_IDLE_TTL_SECONDS,
  );
  pipeline.sadd(adminUserSessionsSetKey(input.adminUserId), sessionId);
  pipeline.expire(adminUserSessionsSetKey(input.adminUserId), Math.ceil(ADMIN_SESSION_MAX_LIFETIME_MS / 1000));
  await pipeline.exec();

  return data;
}

export async function getAdminSession(
  redis: Redis,
  sessionId: string,
): Promise<AdminSessionData | null> {
  const raw = await redis.get(adminSessionRedisKey(sessionId));
  if (!raw) {
    return null;
  }

  let parsed: AdminSessionData;
  try {
    parsed = JSON.parse(raw) as AdminSessionData;
  } catch {
    return null;
  }

  const now = Date.now();
  // Enforce hard 8-hour maximum lifetime even with continuous activity
  if (now - parsed.createdAt > ADMIN_SESSION_MAX_LIFETIME_MS) {
    await destroyAdminSession(redis, sessionId, parsed.adminUserId);
    return null;
  }

  const remainingHardSeconds = Math.max(
    1,
    Math.floor((parsed.createdAt + ADMIN_SESSION_MAX_LIFETIME_MS - now) / 1000),
  );
  const nextTtl = Math.min(ADMIN_SESSION_IDLE_TTL_SECONDS, remainingHardSeconds);

  const updated: AdminSessionData = { ...parsed, lastSeenAt: now };
  await redis.set(adminSessionRedisKey(sessionId), JSON.stringify(updated), 'EX', nextTtl);
  return updated;
}

export async function destroyAdminSession(
  redis: Redis,
  sessionId: string,
  adminUserId?: string,
): Promise<void> {
  const pipeline = redis.pipeline();
  pipeline.del(adminSessionRedisKey(sessionId));
  if (adminUserId) {
    pipeline.srem(adminUserSessionsSetKey(adminUserId), sessionId);
  }
  await pipeline.exec();
}

export async function destroyAllAdminSessions(redis: Redis, adminUserId: string): Promise<void> {
  const setKey = adminUserSessionsSetKey(adminUserId);
  const ids = await redis.smembers(setKey);
  const keys = [setKey, ...ids.map((id) => adminSessionRedisKey(id))];
  if (keys.length > 0) {
    await redis.del(...keys);
  }
}

export function setAdminSessionCookie(
  reply: FastifyReply,
  nodeEnv: string,
  session: AdminSessionData,
): void {
  reply.setCookie(getAdminSessionCookieName(nodeEnv), session.sessionId, {
    httpOnly: true,
    secure: nodeEnv === 'production',
    sameSite: 'lax',
    path: '/',
  });
}

export function clearAdminSessionCookie(reply: FastifyReply, nodeEnv: string): void {
  reply.clearCookie(getAdminSessionCookieName(nodeEnv), {
    httpOnly: true,
    secure: nodeEnv === 'production',
    sameSite: 'lax',
    path: '/',
  });
}

export function extractAdminSessionId(request: FastifyRequest, nodeEnv: string): string | null {
  const cookieName = getAdminSessionCookieName(nodeEnv);
  const val = request.cookies?.[cookieName];
  return typeof val === 'string' && val.length > 0 ? val : null;
}
