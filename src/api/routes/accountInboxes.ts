import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import { z } from 'zod';
import {
  destroyUserSession,
  extractUserSessionId,
  getUserSession,
  hasValidCsrfHeader,
} from '../../auth/session.js';
import type { EnvConfig } from '../../config/env.js';
import type { AccountInboxStore } from '../../storage/accountInboxStore.js';
import type { AuthStore, UserRecord } from '../../storage/authStore.js';
import { getEntitlements } from '../../storage/plans.js';
import { inboxExists, redisKeys } from '../../storage/redis.js';
import { formatEmailAddress, generateLocalPart } from '../../utils/address.js';
import { validateCustomName } from '../../utils/customName.js';
import { ApiError } from '../errors.js';

export interface AccountInboxRoutesDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly authStore: AuthStore;
  readonly accountInboxStore: AccountInboxStore;
  readonly getAllowedDomains?: () => readonly string[];
}

const createAccountInboxSchema = z
  .object({
    domain: z.string().trim().toLowerCase().min(1).max(253).optional(),
    customName: z.string().trim().min(1).max(64).optional(),
    ttlMinutes: z.number().int().min(1).optional(),
  })
  .optional()
  .default({});

const inboxIdParamSchema = z.object({
  id: z.string().trim().min(1).max(128),
});

const inboxMessageParamSchema = inboxIdParamSchema.extend({
  msgId: z.string().trim().min(1).max(128),
});

export async function registerAccountInboxRoutes(
  app: FastifyInstance,
  deps: AccountInboxRoutesDependencies,
): Promise<void> {
  const { config, redis, authStore, accountInboxStore, getAllowedDomains } = deps;

  const resolveAllowedDomains = (): readonly string[] =>
    getAllowedDomains ? getAllowedDomains() : config.allowedDomains;

  const requireUser = async (
    request: FastifyRequest,
    requireCsrf: boolean,
  ): Promise<UserRecord> => {
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

    return user;
  };

  // GET /api/v1/account/inboxes
  app.get('/account/inboxes', async (request) => {
    const user = await requireUser(request, false);
    const inboxes = await accountInboxStore.listUserInboxes(user.id);

    return {
      inboxes: inboxes.map((inbox) => ({
        id: inbox.id,
        address: inbox.address,
        customName: inbox.customName,
        createdAt: inbox.createdAt.toISOString(),
        expiresAt: inbox.expiresAt.toISOString(),
      })),
    };
  });

  // POST /api/v1/account/inboxes
  app.post('/account/inboxes', async (request, reply) => {
    const user = await requireUser(request, true);
    const body = createAccountInboxSchema.parse(request.body ?? {});
    const plansMap = await authStore.loadPlansMap();
    const entitlements = getEntitlements(user, plansMap);

    const allowedDomains = resolveAllowedDomains();
    const domain = body.domain ?? allowedDomains[0] ?? config.primaryDomain;
    if (!allowedDomains.includes(domain)) {
      throw new ApiError(400, 'INVALID_DOMAIN', 'Requested domain is not available');
    }

    const ttlMinutes = body.ttlMinutes ?? entitlements.maxInboxLifetimeMinutes;
    if (ttlMinutes > entitlements.maxInboxLifetimeMinutes) {
      throw new ApiError(
        403,
        'PLAN_LIMIT_EXCEEDED',
        `Your plan allows a maximum inbox lifetime of ${entitlements.maxInboxLifetimeMinutes} minutes`,
      );
    }

    const existingInboxes = await accountInboxStore.listUserInboxes(user.id);
    if (existingInboxes.length >= entitlements.maxActiveAddresses) {
      throw new ApiError(
        403,
        'PLAN_LIMIT_EXCEEDED',
        `Your plan allows at most ${entitlements.maxActiveAddresses} active addresses`,
      );
    }

    let address: string;
    let isCustom = false;

    if (body.customName) {
      const currentCustomCount = existingInboxes.filter((i) => i.customName).length;
      if (currentCustomCount >= entitlements.maxReservedCustomNames) {
        throw new ApiError(
          403,
          'PLAN_LIMIT_EXCEEDED',
          `Your plan allows at most ${entitlements.maxReservedCustomNames} custom name(s)`,
        );
      }

      const nameCheck = validateCustomName(body.customName);
      if (!nameCheck.valid) {
        throw new ApiError(400, 'INVALID_CUSTOM_NAME', nameCheck.reason ?? 'Invalid custom name');
      }

      if (await accountInboxStore.isReservedName(nameCheck.normalized)) {
        throw new ApiError(400, 'RESERVED_NAME', 'This address name is reserved and cannot be used');
      }

      address = formatEmailAddress(nameCheck.normalized, domain);
      isCustom = true;

      const takenInRedis = await inboxExists(redis, address);
      const takenInDb = await accountInboxStore.findActiveInboxByAddress(address);
      if (takenInRedis || takenInDb) {
        throw new ApiError(409, 'ADDRESS_TAKEN', 'This address is already in use');
      }
    } else {
      let generated: string | null = null;
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const candidate = formatEmailAddress(generateLocalPart(), domain);
        const takenInRedis = await inboxExists(redis, candidate);
        const takenInDb = await accountInboxStore.findActiveInboxByAddress(candidate);
        if (!takenInRedis && !takenInDb) {
          generated = candidate;
          break;
        }
      }
      if (!generated) {
        throw new ApiError(500, 'ADDRESS_GENERATION_FAILED', 'Could not allocate unique address');
      }
      address = generated;
    }

    const ttlSeconds = ttlMinutes * 60;
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    const created = await accountInboxStore.createUserInbox({
      userId: user.id,
      address,
      customName: isCustom,
      expiresAt,
    });

    // Register fast Redis marker so SMTP onRcptTo accepts immediately
    await redis.set(redisKeys.acctInbox(address), created.id, 'EX', ttlSeconds);

    return reply.status(201).send({
      id: created.id,
      address: created.address,
      customName: created.customName,
      createdAt: created.createdAt.toISOString(),
      expiresAt: created.expiresAt.toISOString(),
    });
  });

  // DELETE /api/v1/account/inboxes/:id
  app.delete('/account/inboxes/:id', async (request) => {
    const user = await requireUser(request, true);
    const { id } = inboxIdParamSchema.parse(request.params);

    const deleted = await accountInboxStore.deleteUserInbox(user.id, id);
    if (!deleted) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox not found');
    }

    await redis.del(redisKeys.acctInbox(deleted.address));
    return { deleted: true, address: deleted.address };
  });

  // GET /api/v1/account/inboxes/:id/messages
  app.get('/account/inboxes/:id/messages', async (request) => {
    const user = await requireUser(request, false);
    const { id } = inboxIdParamSchema.parse(request.params);
    const inbox = await accountInboxStore.findUserInboxById(user.id, id);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox not found or expired');
    }

    const messages = await accountInboxStore.listAccountMessages(inbox.id);
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

  // GET /api/v1/account/inboxes/:id/messages/:msgId
  app.get('/account/inboxes/:id/messages/:msgId', async (request) => {
    const user = await requireUser(request, false);
    const { id, msgId } = inboxMessageParamSchema.parse(request.params);
    const inbox = await accountInboxStore.findUserInboxById(user.id, id);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox not found or expired');
    }

    const message = await accountInboxStore.getAccountMessage(inbox.id, msgId);
    if (!message) {
      throw new ApiError(404, 'MESSAGE_NOT_FOUND', 'Message not found');
    }

    return message;
  });
}
