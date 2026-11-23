import { createHash, randomBytes } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';

export const SESSION_TTL_DEFAULT_SECONDS = 24 * 60 * 60; // 24 hours (browser session cookie)
export const SESSION_TTL_REMEMBER_SECONDS = 30 * 24 * 60 * 60; // 30 days sliding

export interface UserSessionData {
  readonly sessionId: string;
  readonly userId: string;
  readonly ip: string;
  readonly userAgent: string;
  readonly rememberMe: boolean;
  readonly createdAt: number;
  readonly lastSeenAt: number;
  readonly authAt: number;
}

export function getUserSessionCookieName(nodeEnv: string): string {
  return nodeEnv === 'production' ? '__Host-tm_session' : 'tm_session';
}

export function sessionRedisKey(sessionId: string): string {
  return `sess:user:${sessionId}`;
}

export function userSessionsSetKey(userId: string): string {
  return `user:sessions:${userId}`;
}

export function generateSessionId(): string {
  return randomBytes(32).toString('hex');
}

export function hashToken(rawToken: string): string {
  return createHash('sha256').update(rawToken, 'utf8').digest('hex');
}

export function generateRandomToken(): { readonly raw: string; readonly hash: string } {
  const raw = randomBytes(32).toString('hex');
  return { raw, hash: hashToken(raw) };
}

export async function createUserSession(
  redis: Redis,
  input: {
    readonly userId: string;
    readonly ip: string;
    readonly userAgent: string;
    readonly rememberMe: boolean;
  },
): Promise<UserSessionData> {
  const sessionId = generateSessionId();
  const now = Date.now();
  const ttlSeconds = input.rememberMe ? SESSION_TTL_REMEMBER_SECONDS : SESSION_TTL_DEFAULT_SECONDS;

  const data: UserSessionData = {
    sessionId,
    userId: input.userId,
    ip: input.ip,
    userAgent: input.userAgent.slice(0, 300),
    rememberMe: input.rememberMe,
    createdAt: now,
    lastSeenAt: now,
    authAt: now,
  };

  const pipeline = redis.pipeline();
  pipeline.set(sessionRedisKey(sessionId), JSON.stringify(data), 'EX', ttlSeconds);
  pipeline.sadd(userSessionsSetKey(input.userId), sessionId);
  pipeline.expire(userSessionsSetKey(input.userId), SESSION_TTL_REMEMBER_SECONDS);
  await pipeline.exec();

  return data;
}

export async function getUserSession(
  redis: Redis,
  sessionId: string,
  touch: boolean = true,
): Promise<UserSessionData | null> {
  const raw = await redis.get(sessionRedisKey(sessionId));
  if (!raw) {
    return null;
  }

  let parsed: UserSessionData;
  try {
    parsed = JSON.parse(raw) as UserSessionData;
  } catch {
    return null;
  }

  if (touch) {
    const updated: UserSessionData = {
      ...parsed,
      lastSeenAt: Date.now(),
    };
    const ttlSeconds = parsed.rememberMe
      ? SESSION_TTL_REMEMBER_SECONDS
      : SESSION_TTL_DEFAULT_SECONDS;
    await redis.set(sessionRedisKey(sessionId), JSON.stringify(updated), 'EX', ttlSeconds);
    return updated;
  }

  return parsed;
}

export async function destroyUserSession(
  redis: Redis,
  sessionId: string,
  userId?: string,
): Promise<void> {
  let targetUserId = userId;
  if (!targetUserId) {
    const existing = await getUserSession(redis, sessionId, false);
    targetUserId = existing?.userId;
  }

  const pipeline = redis.pipeline();
  pipeline.del(sessionRedisKey(sessionId));
  if (targetUserId) {
    pipeline.srem(userSessionsSetKey(targetUserId), sessionId);
  }
  await pipeline.exec();
}

export async function destroyAllUserSessions(redis: Redis, userId: string): Promise<number> {
  const setKey = userSessionsSetKey(userId);
  const sessionIds = await redis.smembers(setKey);

  const keysToDelete = [setKey, ...sessionIds.map((id) => sessionRedisKey(id))];
  if (keysToDelete.length > 0) {
    await redis.del(...keysToDelete);
  }

  return sessionIds.length;
}

export async function listUserSessions(redis: Redis, userId: string): Promise<UserSessionData[]> {
  const setKey = userSessionsSetKey(userId);
  const sessionIds = await redis.smembers(setKey);
  if (sessionIds.length === 0) {
    return [];
  }

  const rawValues = await redis.mget(...sessionIds.map((id) => sessionRedisKey(id)));
  const active: UserSessionData[] = [];
  const staleIds: string[] = [];

  for (let i = 0; i < sessionIds.length; i += 1) {
    const id = sessionIds[i];
    const raw = rawValues[i];
    if (!id) continue;
    if (!raw) {
      staleIds.push(id);
      continue;
    }
    try {
      active.push(JSON.parse(raw) as UserSessionData);
    } catch {
      staleIds.push(id);
    }
  }

  if (staleIds.length > 0) {
    await redis.srem(setKey, ...staleIds);
  }

  return active.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
}

export function setUserSessionCookie(
  reply: FastifyReply,
  nodeEnv: string,
  session: UserSessionData,
): void {
  const cookieName = getUserSessionCookieName(nodeEnv);
  reply.setCookie(cookieName, session.sessionId, {
    httpOnly: true,
    secure: nodeEnv === 'production',
    sameSite: 'lax',
    path: '/',
    ...(session.rememberMe ? { maxAge: SESSION_TTL_REMEMBER_SECONDS } : {}),
  });
}

export function clearUserSessionCookie(reply: FastifyReply, nodeEnv: string): void {
  const cookieName = getUserSessionCookieName(nodeEnv);
  reply.clearCookie(cookieName, {
    httpOnly: true,
    secure: nodeEnv === 'production',
    sameSite: 'lax',
    path: '/',
  });
}

export function extractUserSessionId(request: FastifyRequest, nodeEnv: string): string | null {
  const cookieName = getUserSessionCookieName(nodeEnv);
  const value = request.cookies?.[cookieName];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * CSRF check for state-changing requests authenticated via session cookie.
 * Requires a custom header (`x-requested-with` or `x-csrf-token`) that cross-site HTML forms cannot forge.
 */
export function hasValidCsrfHeader(request: FastifyRequest): boolean {
  const xrw = request.headers['x-requested-with'];
  if (typeof xrw === 'string' && xrw.trim().length > 0) {
    return true;
  }
  const csrf = request.headers['x-csrf-token'];
  if (typeof csrf === 'string' && csrf.trim().length > 0) {
    return true;
  }
  return false;
}
