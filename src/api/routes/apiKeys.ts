import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { z } from 'zod';
import { ALL_API_KEY_SCOPES, generateApiKey, type ApiKeyScope } from '../../auth/apiKey.js';
import {
  destroyUserSession,
  extractUserSessionId,
  getUserSession,
  hasValidCsrfHeader,
  type UserSessionData,
} from '../../auth/session.js';
import type { EnvConfig } from '../../config/env.js';
import type { Mailer } from '../../mail/mailer.js';
import type { ApiKeyRecord, ApiKeyStore } from '../../storage/apiKeyStore.js';
import type { AuthStore, UserRecord } from '../../storage/authStore.js';
import { getEntitlements } from '../../storage/plans.js';
import { ApiError } from '../errors.js';

export interface ApiKeyRoutesDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  readonly authStore: AuthStore;
  readonly apiKeyStore: ApiKeyStore;
  readonly mailer: Mailer;
}

const REAUTH_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

const scopeEnum = z.enum(ALL_API_KEY_SCOPES);

const createApiKeySchema = z.object({
  name: z.string().trim().min(1).max(80),
  scopes: z.array(scopeEnum).min(1).optional(),
});

const updateApiKeySchema = z
  .object({
    name: z.string().trim().min(1).max(80).optional(),
    scopes: z.array(scopeEnum).min(1).optional(),
  })
  .refine((v) => v.name !== undefined || v.scopes !== undefined, {
    message: 'At least one field (name or scopes) must be provided',
  });

const keyIdParamSchema = z.object({
  id: z.string().trim().min(1).max(128),
});

function formatApiKeyPublic(key: ApiKeyRecord) {
  return {
    id: key.id,
    name: key.name,
    keyPrefix: key.keyPrefix,
    last4: key.last4,
    scopes: key.scopes,
    createdAt: key.createdAt.toISOString(),
    lastUsedAt: key.lastUsedAt ? key.lastUsedAt.toISOString() : null,
    lastIp: key.lastIp,
    revokedAt: key.revokedAt ? key.revokedAt.toISOString() : null,
  };
}

export async function registerApiKeyRoutes(
  app: FastifyInstance,
  deps: ApiKeyRoutesDependencies,
): Promise<void> {
  const { config, redis, logger, authStore, apiKeyStore, mailer } = deps;

  const requireSession = async (
    request: FastifyRequest,
    requireCsrf: boolean,
  ): Promise<{ session: UserSessionData; user: UserRecord }> => {
    if (requireCsrf && !hasValidCsrfHeader(request)) {
      throw new ApiError(403, 'CSRF_REQUIRED', 'Missing required CSRF protection header');
    }

    const sessionId = extractUserSessionId(request, config.nodeEnv);
    if (!sessionId) {
      throw new ApiError(401, 'UNAUTHENTICATED', 'Authentication required');
    }

    const session = await getUserSession(redis, sessionId, true);
    if (!session) {
      throw new ApiError(401, 'UNAUTHENTICATED', 'Session expired or invalid');
    }

    const user = await authStore.findUserById(session.userId);
    if (!user || user.status !== 'active') {
      await destroyUserSession(redis, sessionId, session.userId);
      throw new ApiError(401, 'UNAUTHENTICATED', 'Account is not active');
    }

    return { session, user };
  };

  // GET /api/v1/account/api-keys
  app.get('/account/api-keys', async (request) => {
    const { user } = await requireSession(request, false);
    const keys = await apiKeyStore.listUserApiKeys(user.id);
    return {
      apiKeys: keys.map(formatApiKeyPublic),
    };
  });

  // POST /api/v1/account/api-keys
  app.post('/account/api-keys', async (request, reply) => {
    const { session, user } = await requireSession(request, true);

    if (!user.emailVerifiedAt) {
      throw new ApiError(
        403,
        'EMAIL_VERIFICATION_REQUIRED',
        'Verify your email address before creating an API key',
      );
    }

    if (Date.now() - session.authAt > REAUTH_WINDOW_MS) {
      throw new ApiError(
        403,
        'REAUTH_REQUIRED',
        'Please re-authenticate before creating a new API key',
      );
    }

    const body = createApiKeySchema.parse(request.body);
    const plansMap = await authStore.loadPlansMap();
    const entitlements = getEntitlements(user, plansMap);

    const activeCount = await apiKeyStore.countActiveUserApiKeys(user.id);
    if (activeCount >= entitlements.maxApiKeys) {
      throw new ApiError(
        403,
        'PLAN_LIMIT_EXCEEDED',
        `Your plan allows at most ${entitlements.maxApiKeys} active API keys`,
      );
    }

    const scopes: readonly ApiKeyScope[] = body.scopes
      ? Array.from(new Set(body.scopes))
      : [...ALL_API_KEY_SCOPES];

    const generated = generateApiKey();
    const record = await apiKeyStore.createApiKey({
      userId: user.id,
      name: body.name,
      keyPrefix: generated.keyPrefix,
      last4: generated.last4,
      keyHash: generated.keyHash,
      scopes,
    });

    await mailer
      .sendEmail(user.email, 'api_key_created', {
        keyName: record.name,
        keyPrefix: record.keyPrefix,
        scopes: record.scopes,
        time: new Date().toISOString(),
      })
      .catch((err) => {
        logger.warn({ err, userId: user.id, keyId: record.id }, 'Failed to send api_key_created email');
      });

    // Full key is returned ONCE here and never stored or retrievable again
    return reply.status(201).send({
      apiKey: formatApiKeyPublic(record),
      key: generated.fullKey,
    });
  });

  // PATCH /api/v1/account/api-keys/:id
  app.patch('/account/api-keys/:id', async (request) => {
    const { user } = await requireSession(request, true);
    const { id } = keyIdParamSchema.parse(request.params);
    const body = updateApiKeySchema.parse(request.body);

    const updated = await apiKeyStore.updateApiKey(user.id, id, {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.scopes !== undefined ? { scopes: Array.from(new Set(body.scopes)) } : {}),
    });

    if (!updated) {
      throw new ApiError(404, 'API_KEY_NOT_FOUND', 'Active API key not found');
    }

    return { apiKey: formatApiKeyPublic(updated) };
  });

  // DELETE /api/v1/account/api-keys/:id
  app.delete('/account/api-keys/:id', async (request) => {
    const { user } = await requireSession(request, true);
    const { id } = keyIdParamSchema.parse(request.params);

    const revoked = await apiKeyStore.revokeApiKey(user.id, id);
    if (!revoked) {
      throw new ApiError(404, 'API_KEY_NOT_FOUND', 'Active API key not found');
    }

    return { revoked: true };
  });

  // GET /api/v1/account/api-keys/:id/usage
  app.get('/account/api-keys/:id/usage', async (request) => {
    const { user } = await requireSession(request, false);
    const { id } = keyIdParamSchema.parse(request.params);

    const usage = await apiKeyStore.getApiKeyUsage(user.id, id, 30);
    if (usage === null) {
      throw new ApiError(404, 'API_KEY_NOT_FOUND', 'API key not found');
    }

    return { usage };
  });
}
