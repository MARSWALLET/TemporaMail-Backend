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
import type { EnvConfig } from '../config/env.js';
import { ApiError, formatApiError } from './errors.js';
import { registerV1Routes } from './routes/v1.js';

export interface ApiAppDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  /** Pass Redis instance for distributed rate limiting in production/dev; omit in mock unit tests. */
  readonly rateLimitRedis?: Redis;
  readonly getAllowedDomains?: () => readonly string[];
  readonly verifyTurnstile?: (token: string, ip: string) => Promise<boolean>;
}

export async function createApiApp(deps: ApiAppDependencies): Promise<FastifyInstance> {
  const { config, redis, logger, rateLimitRedis, getAllowedDomains, verifyTurnstile } = deps;

  const app = Fastify({
    loggerInstance: logger as FastifyBaseLogger,
    trustProxy: true,
  });

  await app.register(helmet);

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
        ...(getAllowedDomains ? { getAllowedDomains } : {}),
        ...(verifyTurnstile ? { verifyTurnstile } : {}),
      });
    },
    { prefix: '/api/v1' },
  );

  return app;
}
