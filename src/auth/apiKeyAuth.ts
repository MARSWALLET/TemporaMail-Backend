import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { ApiError } from '../api/errors.js';
import type { ApiKeyStore, ApiKeyRecord } from '../storage/apiKeyStore.js';
import type { AuthStore } from '../storage/authStore.js';
import { getEntitlements, type PlanEntitlements } from '../storage/plans.js';
import { hashApiKey, isApiKeyToken, type ApiKeyScope } from './apiKey.js';

export interface AuthenticatedApiKeyContext {
  readonly key: ApiKeyRecord;
  readonly entitlements: PlanEntitlements;
}

export interface ApiKeyAuthDeps {
  readonly redis: Redis;
  readonly apiKeyStore: ApiKeyStore;
  readonly authStore?: AuthStore;
  readonly logger: Logger;
}

function getTodayUtcDate(): string {
  return new Date().toISOString().slice(0, 10);
}

function secondsUntilNextUtcMidnight(): number {
  const now = new Date();
  const nextMidnight = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
    0,
    0,
    0,
  );
  return Math.max(1, Math.ceil((nextMidnight - now.getTime()) / 1000));
}

export function extractBearerApiKey(request: FastifyRequest): string | null {
  const authHeader = request.headers.authorization;
  if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authHeader.slice('Bearer '.length).trim();
  return isApiKeyToken(token) ? token : null;
}

/**
 * If the request carries `Authorization: Bearer tm_live_...`, validates the API key,
 * checks owner status, enforces scope, enforces per-key daily rate limit (429 + Retry-After),
 * and records usage. Returns null if no API key header is present.
 */
export async function authenticateOptionalApiKey(
  request: FastifyRequest,
  reply: FastifyReply,
  requiredScope: ApiKeyScope,
  deps: ApiKeyAuthDeps,
): Promise<AuthenticatedApiKeyContext | null> {
  const rawKey = extractBearerApiKey(request);
  if (!rawKey) {
    return null;
  }

  const keyHash = hashApiKey(rawKey);
  const found = await deps.apiKeyStore.findApiKeyByHash(keyHash);

  if (!found || found.key.revokedAt !== null || found.userStatus !== 'active') {
    throw new ApiError(401, 'INVALID_API_KEY', 'API key is invalid or has been revoked');
  }

  if (!found.key.scopes.includes(requiredScope)) {
    throw new ApiError(
      403,
      'INSUFFICIENT_SCOPE',
      `API key is missing required scope: ${requiredScope}`,
    );
  }

  const plansMap = deps.authStore ? await deps.authStore.loadPlansMap() : undefined;
  const entitlements = getEntitlements(
    { planId: found.userPlanId, status: found.userStatus },
    plansMap,
  );

  const today = getTodayUtcDate();
  const rlKey = `rl:apikey:${found.key.id}:${today}`;
  const currentCount = await deps.redis.incr(rlKey);
  const ttlSeconds = secondsUntilNextUtcMidnight();
  if (currentCount === 1) {
    await deps.redis.expire(rlKey, ttlSeconds);
  }

  if (entitlements.apiRequestsPerDay <= 0 || currentCount > entitlements.apiRequestsPerDay) {
    reply.header('Retry-After', String(ttlSeconds));
    throw new ApiError(
      429,
      'API_KEY_RATE_LIMIT_EXCEEDED',
      `Daily API key request limit (${entitlements.apiRequestsPerDay}) exceeded`,
    );
  }

  void deps.apiKeyStore.recordApiKeyUsage(found.key.id, request.ip, today).catch((err) => {
    deps.logger.warn({ err, keyId: found.key.id }, 'Failed to persist API key usage');
  });

  return {
    key: found.key,
    entitlements,
  };
}
