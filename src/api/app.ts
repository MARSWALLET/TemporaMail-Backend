import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, {
  type FastifyBaseLogger,
  type FastifyInstance,
  type FastifyRequest,
} from 'fastify';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { ZodError } from 'zod';
import type { GoogleOAuthClient } from '../auth/googleOAuth.js';
import type { EnvConfig } from '../config/env.js';
import type { Mailer } from '../mail/mailer.js';
import type { AccountInboxStore } from '../storage/accountInboxStore.js';
import type { AdminStore } from '../storage/adminStore.js';
import type { ApiKeyStore } from '../storage/apiKeyStore.js';
import type { AuthStore } from '../storage/authStore.js';
import { InboxEventHub } from '../stream/pubsub.js';
import { registerSseRoute } from '../stream/sse.js';
import { ApiError, formatApiError } from './errors.js';
import { registerAccountInboxRoutes } from './routes/accountInboxes.js';
import { registerAdminRoutes } from './routes/admin.js';
import { registerApiKeyRoutes } from './routes/apiKeys.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerOAuthRoutes } from './routes/oauth.js';
import { registerTwoFactorRoutes } from './routes/twoFactor.js';
import { registerV1Routes } from './routes/v1.js';

export interface ApiAppDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  /** Pass Redis instance for distributed rate limiting in production/dev; omit in mock unit tests. */
  readonly rateLimitRedis?: Redis;
  /** Optional shared SSE event hub; created automatically from redis.duplicate() when omitted. */
  readonly eventHub?: InboxEventHub;
  readonly sseHeartbeatMs?: number;
  readonly getAllowedDomains?: () => readonly string[];
  readonly verifyTurnstile?: (token: string, ip: string) => Promise<boolean>;
  readonly adminStore?: AdminStore;
  readonly authStore?: AuthStore;
  readonly accountInboxStore?: AccountInboxStore;
  readonly apiKeyStore?: ApiKeyStore;
  readonly mailer?: Mailer;
  readonly googleOAuthClient?: GoogleOAuthClient;
  readonly onLiveSettingsMutated?: () => Promise<void>;
}

export async function createApiApp(deps: ApiAppDependencies): Promise<FastifyInstance> {
  const {
    config,
    redis,
    logger,
    rateLimitRedis,
    eventHub: providedEventHub,
    sseHeartbeatMs,
    getAllowedDomains,
    verifyTurnstile,
    adminStore,
    authStore,
    accountInboxStore,
    apiKeyStore,
    mailer,
    googleOAuthClient,
    onLiveSettingsMutated,
  } = deps;

  const ownsEventHub = !providedEventHub;
  const eventHub = providedEventHub ?? new InboxEventHub(redis.duplicate(), logger);
  await eventHub.start();

  const app = Fastify({
    loggerInstance: logger as FastifyBaseLogger,
    trustProxy: true,
  });

  await app.register(helmet);
  await app.register(cookie);

  await app.register(cors, {
    origin: (origin, callback) => {
      // Allow non-browser requests (curl, server-to-server) that omit Origin
      if (!origin) {
        callback(null, true);
        return;
      }
      if (config.corsOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new ApiError(403, 'CORS_FORBIDDEN', 'Origin not allowed'), false);
    },
    credentials: true,
  });

  await app.register(rateLimit, {
    global: true,
    max: config.apiRateLimitPerMin,
    timeWindow: '1 minute',
    ...(rateLimitRedis ? { redis: rateLimitRedis } : {}),
    keyGenerator: (request: FastifyRequest) => `rl:api:${request.ip}`,
    errorResponseBuilder: (_request, context) => ({
      statusCode: 429,
      ...formatApiError(
        'RATE_LIMIT_EXCEEDED',
        `Rate limit exceeded. Retry in ${context.after}.`,
      ),
    }),
  });

  app.setNotFoundHandler((_request, reply) => {
    return reply.status(404).send(formatApiError('NOT_FOUND', 'Route not found'));
  });

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send(formatApiError(error.code, error.message));
    }

    if (error instanceof ZodError) {
      const firstIssue = error.issues[0];
      const message = firstIssue
        ? `${firstIssue.path.join('.') || 'input'}: ${firstIssue.message}`
        : 'Invalid request payload';
      return reply.status(400).send(formatApiError('VALIDATION_ERROR', message));
    }

    const fastifyErr = error as { statusCode?: number; code?: string; message?: string };
    if (fastifyErr.statusCode === 429) {
      return reply
        .status(429)
        .send(formatApiError('RATE_LIMIT_EXCEEDED', fastifyErr.message ?? 'Rate limit exceeded'));
    }

    if (fastifyErr.statusCode && fastifyErr.statusCode >= 400 && fastifyErr.statusCode < 500) {
      return reply
        .status(fastifyErr.statusCode)
        .send(formatApiError(fastifyErr.code ?? 'BAD_REQUEST', fastifyErr.message ?? 'Bad request'));
    }

    logger.error({ err: error }, 'Unhandled API error');
    return reply
      .status(500)
      .send(formatApiError('INTERNAL_ERROR', 'An unexpected error occurred'));
  });

  await app.register(
    async (v1) => {
      await registerV1Routes(v1, {
        config,
        redis,
        logger,
        ...(apiKeyStore ? { apiKeyStore } : {}),
        ...(authStore ? { authStore } : {}),
        ...(getAllowedDomains ? { getAllowedDomains } : {}),
        ...(verifyTurnstile ? { verifyTurnstile } : {}),
      });
      await registerSseRoute(v1, {
        config,
        redis,
        logger,
        eventHub,
        ...(accountInboxStore ? { accountInboxStore } : {}),
        ...(sseHeartbeatMs !== undefined ? { heartbeatMs: sseHeartbeatMs } : {}),
      });
      if (authStore && mailer) {
        await registerAuthRoutes(v1, {
          config,
          redis,
          logger,
          authStore,
          mailer,
          ...(getAllowedDomains ? { getAllowedDomains } : {}),
          ...(verifyTurnstile ? { verifyTurnstile } : {}),
        });
        await registerOAuthRoutes(v1, {
          config,
          redis,
          logger,
          authStore,
          ...(googleOAuthClient ? { googleClient: googleOAuthClient } : {}),
        });
        await registerTwoFactorRoutes(v1, {
          config,
          redis,
          logger,
          authStore,
          mailer,
        });
        if (accountInboxStore) {
          await registerAccountInboxRoutes(v1, {
            config,
            redis,
            authStore,
            accountInboxStore,
            ...(getAllowedDomains ? { getAllowedDomains } : {}),
          });
        }
        if (apiKeyStore) {
          await registerApiKeyRoutes(v1, {
            config,
            redis,
            logger,
            authStore,
            apiKeyStore,
            mailer,
          });
        }
      }
      if (adminStore) {
        await v1.register(
          async (admin) => {
            await registerAdminRoutes(admin, {
              config,
              redis,
              adminStore,
              ...(onLiveSettingsMutated ? { onLiveSettingsMutated } : {}),
            });
          },
          { prefix: '/admin' },
        );
      }
    },
    { prefix: '/api/v1' },
  );

  if (ownsEventHub) {
    app.addHook('onClose', async () => {
      await eventHub.close();
    });
  }

  return app;
}
