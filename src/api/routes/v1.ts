import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { z } from 'zod';
import { authenticateOptionalApiKey } from '../../auth/apiKeyAuth.js';
import type { EnvConfig } from '../../config/env.js';
import type { ApiKeyStore } from '../../storage/apiKeyStore.js';
import type { AuthStore } from '../../storage/authStore.js';
import {
  createInbox,
  deleteInbox,
  deleteInboxMessage,
  getInbox,
  getInboxMessage,
  getInboxMessageCount,
  getMessageAttachment,
  isIpBanned,
  listInboxMessages,
  setInboxTTL,
} from '../../storage/redis.js';
import { normalizeAddress, verifyOwnerToken } from '../../utils/address.js';
import { ApiError } from '../errors.js';

export interface V1RoutesDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger?: Logger;
  readonly apiKeyStore?: ApiKeyStore;
  readonly authStore?: AuthStore;
  readonly getAllowedDomains?: () => readonly string[];
  readonly verifyTurnstile?: (token: string, ip: string) => Promise<boolean>;
}

const addressParamSchema = z.object({
  address: z
    .string()
    .trim()
    .min(3)
    .max(254)
    .refine((val) => val.includes('@'), { message: 'Invalid email address format' }),
});

const messageParamsSchema = addressParamSchema.extend({
  id: z.string().trim().min(1).max(128),
});

const attachmentParamsSchema = messageParamsSchema.extend({
  index: z.coerce.number().int().min(0).max(100),
});

const createInboxBodySchema = z
  .object({
    domain: z.string().trim().toLowerCase().min(1).max(253).optional(),
    ttlMinutes: z.number().int().min(1).optional(),
    turnstileToken: z.string().trim().min(1).optional(),
  })
  .optional()
  .default({});

const extendInboxBodySchema = z
  .object({
    ttlMinutes: z.number().int().min(1).optional(),
    ownerToken: z.string().trim().min(1).optional(),
  })
  .optional()
  .default({});

function extractOwnerToken(request: FastifyRequest, bodyToken?: string): string | null {
  const headerToken = request.headers['x-owner-token'];
  if (typeof headerToken === 'string' && headerToken.trim().length > 0) {
    return headerToken.trim();
  }

  const authHeader = request.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice('Bearer '.length).trim();
    if (token.length > 0) {
      return token;
    }
  }

  if (bodyToken && bodyToken.trim().length > 0) {
    return bodyToken.trim();
  }

  return null;
}

function sanitizeContentDispositionFilename(filename: string): string {
  return filename.replace(/["\\\r\n]/g, '_');
}

export async function registerV1Routes(
  app: FastifyInstance,
  deps: V1RoutesDependencies,
): Promise<void> {
  const { config, redis, logger, apiKeyStore, authStore, getAllowedDomains, verifyTurnstile } =
    deps;

  const resolveAllowedDomains = (): readonly string[] =>
    getAllowedDomains ? getAllowedDomains() : config.allowedDomains;

  const checkApiKey = async (
    request: FastifyRequest,
    reply: import('fastify').FastifyReply,
    scope: 'inbox:create' | 'inbox:read' | 'inbox:delete' | 'messages:read',
  ) => {
    if (!apiKeyStore) {
      return null;
    }
    return authenticateOptionalApiKey(request, reply, scope, {
      redis,
      apiKeyStore,
      ...(authStore ? { authStore } : {}),
      logger: logger ?? (app.log as unknown as Logger),
    });
  };

  // POST /api/v1/inbox
  app.post(
    '/inbox',
    {
      config: {
        rateLimit: {
          max: config.inboxCreateLimitPerHour,
          timeWindow: '1 hour',
          keyGenerator: (request: FastifyRequest) => `rl:gen:${request.ip}`,
        },
      },
    },
    async (request, reply) => {
      if (await isIpBanned(redis, request.ip)) {
        throw new ApiError(403, 'IP_BANNED', 'Access denied');
      }

      const apiKeyCtx = await checkApiKey(request, reply, 'inbox:create');
      const body = createInboxBodySchema.parse(request.body ?? {});
      const allowedDomains = resolveAllowedDomains();
      const targetDomain = body.domain ?? allowedDomains[0] ?? config.primaryDomain;

      if (!allowedDomains.includes(targetDomain)) {
        throw new ApiError(400, 'INVALID_DOMAIN', 'Requested domain is not available');
      }

      const maxTtlAllowed = apiKeyCtx
        ? apiKeyCtx.entitlements.maxInboxLifetimeMinutes
        : config.maxTtlMinutes;
      const requestedTtlMinutes = body.ttlMinutes ?? config.defaultTtlMinutes;
      if (requestedTtlMinutes > maxTtlAllowed) {
        throw new ApiError(
          400,
          'TTL_EXCEEDS_MAX',
          `ttlMinutes cannot exceed ${maxTtlAllowed}`,
        );
      }

      // Spec 5.3: Skip CAPTCHA requirement for key-authenticated POST /inbox
      if (!apiKeyCtx && config.nodeEnv === 'production') {
        if (!body.turnstileToken) {
          throw new ApiError(400, 'CAPTCHA_REQUIRED', 'Turnstile verification token is required');
        }
        if (verifyTurnstile) {
          const valid = await verifyTurnstile(body.turnstileToken, request.ip);
          if (!valid) {
            throw new ApiError(403, 'CAPTCHA_FAILED', 'Turnstile verification failed');
          }
        }
      }

      const created = await createInbox(redis, {
        domain: targetDomain,
        ttlSeconds: requestedTtlMinutes * 60,
        ip: request.ip,
      });

      return reply.status(201).send({
        address: created.address,
        ownerToken: created.ownerToken,
        expiresAt: new Date(created.expiresAt).toISOString(),
      });
    },
  );

  // GET /api/v1/inbox/:address
  app.get('/inbox/:address', async (request, reply) => {
    await checkApiKey(request, reply, 'inbox:read');
    const { address: rawAddress } = addressParamSchema.parse(request.params);
    const address = normalizeAddress(rawAddress);
    const inbox = await getInbox(redis, address);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    const messageCount = await getInboxMessageCount(redis, address);
    const ttlSeconds = Math.max(0, Math.ceil((inbox.expiresAt - Date.now()) / 1000));

    return {
      address: inbox.address,
      createdAt: new Date(inbox.createdAt).toISOString(),
      expiresAt: new Date(inbox.expiresAt).toISOString(),
      ttlSeconds,
      messageCount,
    };
  });

  // GET /api/v1/inbox/:address/messages
  app.get('/inbox/:address/messages', async (request, reply) => {
    await checkApiKey(request, reply, 'messages:read');
    const { address: rawAddress } = addressParamSchema.parse(request.params);
    const address = normalizeAddress(rawAddress);
    const inbox = await getInbox(redis, address);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    const messages = await listInboxMessages(redis, address);

    return {
      address: inbox.address,
      messages: messages.map((msg) => ({
        id: msg.id,
        from: msg.from,
        subject: msg.subject,
        date: msg.date,
        hasOtp: msg.otp !== null,
        spamFlagged: msg.spamFlagged,
        attachmentCount: msg.attachments.length,
      })),
    };
  });

  // GET /api/v1/inbox/:address/messages/:id
  app.get('/inbox/:address/messages/:id', async (request, reply) => {
    await checkApiKey(request, reply, 'messages:read');
    const { address: rawAddress, id } = messageParamsSchema.parse(request.params);
    const address = normalizeAddress(rawAddress);
    const inbox = await getInbox(redis, address);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    const message = await getInboxMessage(redis, address, id);
    if (!message) {
      throw new ApiError(404, 'MESSAGE_NOT_FOUND', 'Message not found');
    }

    return message;
  });

  // GET /api/v1/inbox/:address/messages/:id/attachments/:index
  app.get('/inbox/:address/messages/:id/attachments/:index', async (request, reply) => {
    const { address: rawAddress, id, index } = attachmentParamsSchema.parse(request.params);
    const address = normalizeAddress(rawAddress);
    const inbox = await getInbox(redis, address);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    const attachment = await getMessageAttachment(redis, address, id, index);
    if (!attachment) {
      throw new ApiError(404, 'ATTACHMENT_NOT_FOUND', 'Attachment not found');
    }

    const safeFilename = sanitizeContentDispositionFilename(attachment.metadata.filename);
    return reply
      .header('Content-Type', attachment.metadata.contentType)
      .header('Content-Disposition', `attachment; filename="${safeFilename}"`)
      .header('X-Content-Type-Options', 'nosniff')
      .send(attachment.content);
  });

  // POST /api/v1/inbox/:address/extend
  app.post('/inbox/:address/extend', async (request) => {
    const { address: rawAddress } = addressParamSchema.parse(request.params);
    const body = extendInboxBodySchema.parse(request.body ?? {});
    const address = normalizeAddress(rawAddress);
    const inbox = await getInbox(redis, address);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    const token = extractOwnerToken(request, body.ownerToken);
    if (!token || !verifyOwnerToken(token, inbox.ownerTokenHash)) {
      throw new ApiError(401, 'UNAUTHORIZED', 'Valid ownerToken is required');
    }

    const addMinutes = body.ttlMinutes ?? config.defaultTtlMinutes;
    const now = Date.now();
    const maxAllowedExpiresAt = inbox.createdAt + config.maxTtlMinutes * 60 * 1000;
    const requestedExpiresAt = Math.max(inbox.expiresAt, now) + addMinutes * 60 * 1000;
    const clampedExpiresAt = Math.min(requestedExpiresAt, maxAllowedExpiresAt);
    const newTtlSeconds = Math.max(1, Math.ceil((clampedExpiresAt - now) / 1000));

    const updated = await setInboxTTL(redis, address, newTtlSeconds);
    if (!updated.updated) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    return {
      address: inbox.address,
      expiresAt: new Date(updated.expiresAt).toISOString(),
      ttlSeconds: newTtlSeconds,
    };
  });

  // DELETE /api/v1/inbox/:address
  app.delete('/inbox/:address', async (request, reply) => {
    await checkApiKey(request, reply, 'inbox:delete');
    const { address: rawAddress } = addressParamSchema.parse(request.params);
    const address = normalizeAddress(rawAddress);
    const inbox = await getInbox(redis, address);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    const token = extractOwnerToken(request);
    if (!token || !verifyOwnerToken(token, inbox.ownerTokenHash)) {
      throw new ApiError(401, 'UNAUTHORIZED', 'Valid ownerToken is required');
    }

    await deleteInbox(redis, address);
    return { deleted: true };
  });

  // DELETE /api/v1/inbox/:address/messages/:id
  app.delete('/inbox/:address/messages/:id', async (request) => {
    const { address: rawAddress, id } = messageParamsSchema.parse(request.params);
    const address = normalizeAddress(rawAddress);
    const inbox = await getInbox(redis, address);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    const token = extractOwnerToken(request);
    if (!token || !verifyOwnerToken(token, inbox.ownerTokenHash)) {
      throw new ApiError(401, 'UNAUTHORIZED', 'Valid ownerToken is required');
    }

    const deleted = await deleteInboxMessage(redis, address, id);
    if (!deleted) {
      throw new ApiError(404, 'MESSAGE_NOT_FOUND', 'Message not found');
    }

    return { deleted: true };
  });

  // GET /api/v1/domains
  app.get('/domains', async () => {
    return {
      domains: resolveAllowedDomains(),
    };
  });

  // GET /api/v1/health
  app.get('/health', async (_request, reply) => {
    try {
      const pong = await redis.ping();
      return {
        status: pong === 'PONG' ? 'ok' : 'degraded',
        redis: pong === 'PONG' ? 'up' : 'degraded',
        timestamp: new Date().toISOString(),
      };
    } catch {
      return reply.status(503).send({
        status: 'error',
        redis: 'down',
        timestamp: new Date().toISOString(),
      });
    }
  });
}
