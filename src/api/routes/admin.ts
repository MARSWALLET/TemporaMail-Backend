import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import { z } from 'zod';
import type { EnvConfig } from '../../config/env.js';
import type { AdminStore } from '../../storage/adminStore.js';
import { deleteInbox } from '../../storage/redis.js';
import { normalizeAddress } from '../../utils/address.js';
import { ApiError } from '../errors.js';

export interface AdminRoutesDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly adminStore: AdminStore;
  readonly onLiveSettingsMutated?: () => Promise<void>;
}

const idParamSchema = z.object({
  id: z.coerce.number().int().min(1),
});

const addressParamSchema = z.object({
  address: z
    .string()
    .trim()
    .min(3)
    .max(254)
    .refine((val) => val.includes('@'), { message: 'Invalid email address format' }),
});

const createDomainSchema = z.object({
  name: z
    .string()
    .trim()
    .toLowerCase()
    .min(3)
    .max(253)
    .regex(/^[a-z0-9.-]+\.[a-z]{2,}$/, 'Invalid domain name'),
  active: z.boolean().optional(),
  notes: z.string().max(500).optional(),
});

const updateDomainSchema = z
  .object({
    active: z.boolean().optional(),
    notes: z.string().max(500).optional(),
  })
  .refine((v) => v.active !== undefined || v.notes !== undefined, {
    message: 'At least one field (active or notes) must be provided',
  });

const createBlocklistSchema = z.object({
  type: z.enum(['sender', 'domain', 'ip', 'keyword']),
  value: z.string().trim().min(1).max(320),
  reason: z.string().trim().max(500).optional(),
});

const settingKeyParamSchema = z.object({
  key: z
    .string()
    .trim()
    .min(1)
    .max(100)
    .regex(/^[a-z0-9_]+$/, 'Setting key must be snake_case alphanumeric'),
});

const updateSettingBodySchema = z.object({
  value: z.unknown().refine((val) => val !== undefined, { message: 'value is required' }),
});

const abuseReportsQuerySchema = z.object({
  status: z.enum(['open', 'resolved', 'dismissed']).optional(),
});

const updateAbuseReportSchema = z.object({
  status: z.enum(['open', 'resolved', 'dismissed']),
});

const smtpLogsQuerySchema = z.object({
  ip: z.string().trim().optional(),
  from: z.string().trim().optional(),
  to: z.string().trim().optional(),
  result: z.enum(['accepted', 'rejected', 'flagged']).optional(),
  reason: z.string().trim().optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
});

const auditLogsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
});

function extractAdminKey(request: FastifyRequest): string | null {
  const headerKey = request.headers['x-admin-api-key'];
  if (typeof headerKey === 'string' && headerKey.trim().length > 0) {
    return headerKey.trim();
  }

  const authHeader = request.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice('Bearer '.length).trim();
    if (token.length > 0) {
      return token;
    }
  }

  return null;
}

function timingSafeKeyEquals(provided: string, expected: string): boolean {
  const providedHash = createHash('sha256').update(provided, 'utf8').digest();
  const expectedHash = createHash('sha256').update(expected, 'utf8').digest();
  return timingSafeEqual(providedHash, expectedHash);
}

async function countActiveInboxes(redis: Redis): Promise<number> {
  let cursor = '0';
  let count = 0;

  do {
    const [nextCursor, keys] = await redis.scan(cursor, 'MATCH', 'inbox:*', 'COUNT', 200);
    cursor = nextCursor;
    for (const key of keys) {
      if (!key.endsWith(':msgs')) {
        count += 1;
      }
    }
  } while (cursor !== '0');

  return count;
}

export async function registerAdminRoutes(
  app: FastifyInstance,
  deps: AdminRoutesDependencies,
): Promise<void> {
  const { config, redis, adminStore, onLiveSettingsMutated } = deps;

  app.addHook('preHandler', async (request) => {
    if (!config.adminApiKey) {
      throw new ApiError(503, 'ADMIN_DISABLED', 'Admin API key is not configured');
    }

    const provided = extractAdminKey(request);
    if (!provided || !timingSafeKeyEquals(provided, config.adminApiKey)) {
      throw new ApiError(401, 'ADMIN_UNAUTHORIZED', 'Invalid or missing admin API key');
    }
  });

  const actorFor = (request: FastifyRequest): string => `admin_api_key:${request.ip}`;

  // GET /api/v1/admin/stats
  app.get('/stats', async () => {
    const [smtpStats, activeInboxes] = await Promise.all([
      adminStore.getSmtpStatsLastHour(),
      countActiveInboxes(redis),
    ]);

    return {
      emailsLastHour: smtpStats.emailsLastHour,
      activeInboxes,
      rejectionsByReason: smtpStats.rejectionsByReason,
      timestamp: new Date().toISOString(),
    };
  });

  // --- Domains CRUD ---
  app.get('/domains', async () => {
    const domains = await adminStore.listDomains();
    return { domains };
  });

  app.post('/domains', async (request, reply) => {
    const body = createDomainSchema.parse(request.body);
    const created = await adminStore.createDomain({
      name: body.name,
      ...(body.active !== undefined ? { active: body.active } : {}),
      ...(body.notes !== undefined ? { notes: body.notes } : {}),
    });

    await adminStore.insertAuditLog({
      actor: actorFor(request),
      action: 'domain.create',
      target: created.name,
      details: { id: created.id, active: created.active, notes: created.notes },
    });

    if (onLiveSettingsMutated) {
      await onLiveSettingsMutated();
    }

    return reply.status(201).send(created);
  });

  app.patch('/domains/:id', async (request) => {
    const { id } = idParamSchema.parse(request.params);
    const body = updateDomainSchema.parse(request.body);
    const updated = await adminStore.updateDomain(id, {
      ...(body.active !== undefined ? { active: body.active } : {}),
      ...(body.notes !== undefined ? { notes: body.notes } : {}),
    });

    if (!updated) {
      throw new ApiError(404, 'DOMAIN_NOT_FOUND', 'Domain not found');
    }

    await adminStore.insertAuditLog({
      actor: actorFor(request),
      action: 'domain.update',
      target: updated.name,
      details: { id, ...body },
    });

    if (onLiveSettingsMutated) {
      await onLiveSettingsMutated();
    }

    return updated;
  });

  app.delete('/domains/:id', async (request) => {
    const { id } = idParamSchema.parse(request.params);
    const deleted = await adminStore.deleteDomain(id);

    if (!deleted) {
      throw new ApiError(404, 'DOMAIN_NOT_FOUND', 'Domain not found');
    }

    await adminStore.insertAuditLog({
      actor: actorFor(request),
      action: 'domain.delete',
      target: String(id),
      details: { id },
    });

    if (onLiveSettingsMutated) {
      await onLiveSettingsMutated();
    }

    return { deleted: true };
  });

  // --- Blocklist CRUD ---
  app.get('/blocklist', async () => {
    const entries = await adminStore.listBlocklist();
    return { entries };
  });

  app.post('/blocklist', async (request, reply) => {
    const body = createBlocklistSchema.parse(request.body);
    const created = await adminStore.addBlocklistEntry({
      type: body.type,
      value: body.value,
      ...(body.reason !== undefined ? { reason: body.reason } : {}),
    });

    await adminStore.insertAuditLog({
      actor: actorFor(request),
      action: 'blocklist.add',
      target: `${created.type}:${created.value}`,
      details: { id: created.id, reason: created.reason },
    });

    if (onLiveSettingsMutated) {
      await onLiveSettingsMutated();
    }

    return reply.status(201).send(created);
  });

  app.delete('/blocklist/:id', async (request) => {
    const { id } = idParamSchema.parse(request.params);
    const deleted = await adminStore.deleteBlocklistEntry(id);

    if (!deleted) {
      throw new ApiError(404, 'BLOCKLIST_NOT_FOUND', 'Blocklist entry not found');
    }

    await adminStore.insertAuditLog({
      actor: actorFor(request),
      action: 'blocklist.delete',
      target: String(id),
      details: { id },
    });

    if (onLiveSettingsMutated) {
      await onLiveSettingsMutated();
    }

    return { deleted: true };
  });

  // --- Settings ---
  app.get('/settings', async () => {
    const rows = await adminStore.listSettings();
    return { settings: rows };
  });

  app.put('/settings/:key', async (request) => {
    const { key } = settingKeyParamSchema.parse(request.params);
    const { value } = updateSettingBodySchema.parse(request.body);
    const updated = await adminStore.upsertSetting(key, value);

    await adminStore.insertAuditLog({
      actor: actorFor(request),
      action: 'settings.update',
      target: key,
      details: { value },
    });

    if (onLiveSettingsMutated) {
      await onLiveSettingsMutated();
    }

    return updated;
  });

  // --- Abuse reports ---
  app.get('/abuse-reports', async (request) => {
    const query = abuseReportsQuerySchema.parse(request.query);
    const reports = await adminStore.listAbuseReports(query.status);
    return { reports };
  });

  app.patch('/abuse-reports/:id', async (request) => {
    const { id } = idParamSchema.parse(request.params);
    const { status } = updateAbuseReportSchema.parse(request.body);
    const updated = await adminStore.updateAbuseReportStatus(id, status);

    if (!updated) {
      throw new ApiError(404, 'ABUSE_REPORT_NOT_FOUND', 'Abuse report not found');
    }

    await adminStore.insertAuditLog({
      actor: actorFor(request),
      action: 'abuse_report.update',
      target: String(id),
      details: { status },
    });

    return updated;
  });

  // --- SMTP Logs ---
  app.get('/smtp-logs', async (request) => {
    const query = smtpLogsQuerySchema.parse(request.query);
    const logs = await adminStore.searchSmtpLogs({
      ...(query.ip ? { ip: query.ip } : {}),
      ...(query.from ? { from: query.from } : {}),
      ...(query.to ? { to: query.to } : {}),
      ...(query.result ? { result: query.result } : {}),
      ...(query.reason ? { reason: query.reason } : {}),
      ...(query.limit !== undefined ? { limit: query.limit } : {}),
    });
    return { logs };
  });

  // --- Inbox Abuse Takedown ---
  app.delete('/inboxes/:address', async (request) => {
    const { address: rawAddress } = addressParamSchema.parse(request.params);
    const address = normalizeAddress(rawAddress);
    const deleted = await deleteInbox(redis, address);

    if (!deleted) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    await adminStore.insertAuditLog({
      actor: actorFor(request),
      action: 'inbox.takedown',
      target: address,
      details: { deleted: true },
    });

    return { deleted: true, address };
  });

  // --- Audit Logs ---
  app.get('/audit-logs', async (request) => {
    const query = auditLogsQuerySchema.parse(request.query);
    const logs = await adminStore.listAuditLogs(query.limit);
    return { logs };
  });
}
