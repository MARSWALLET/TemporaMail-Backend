import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { z } from 'zod';
import { hasAdminPermission, type AdminPermission, type AdminRole } from '../../admin/permissions.js';
import {
  clearAdminSessionCookie,
  createAdminSession,
  destroyAllAdminSessions,
  destroyAdminSession,
  extractAdminSessionId,
  getAdminSession,
  setAdminSessionCookie,
  type AdminSessionData,
} from '../../admin/session.js';
import { hashPassword, validatePasswordStrength, verifyPassword } from '../../auth/password.js';
import {
  destroyAllUserSessions,
  generateRandomToken,
  hashToken,
  hasValidCsrfHeader,
} from '../../auth/session.js';
import {
  createTotpEnrollment,
  decryptTotpSecret,
  encryptTotpSecret,
  generateRecoveryCodes,
  hashRecoveryCode,
  verifyTotpCode,
} from '../../auth/totp.js';
import type { EnvConfig } from '../../config/env.js';
import type { Mailer } from '../../mail/mailer.js';
import type { AccountInboxStore } from '../../storage/accountInboxStore.js';
import type { AdminPanelStore, AdminUserRecord } from '../../storage/adminPanelStore.js';
import type { AdminStore } from '../../storage/adminStore.js';
import { deleteInbox, getInbox, listInboxMessages } from '../../storage/redis.js';
import { normalizeAddress } from '../../utils/address.js';
import { ApiError } from '../errors.js';

export interface AdminPanelRoutesDeps {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  readonly adminStore: AdminStore;
  readonly adminPanelStore: AdminPanelStore;
  readonly accountInboxStore?: AccountInboxStore;
  readonly mailer?: Mailer;
  readonly ipAllowlist?: readonly string[];
  readonly onLiveSettingsMutated?: () => Promise<void>;
}

const ADMIN_LOGIN_MAX_FAILURES = 5;
const ADMIN_LOCKOUT_SECONDS = 30 * 60;
const ADMIN_MFA_PENDING_TTL_SECONDS = 300;

const adminLoginSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(128),
});

const adminMfaSchema = z.object({
  mfaToken: z.string().trim().min(16).max(256),
  code: z.string().trim().min(6).max(20),
});

const inboxLookupSchema = z.object({
  address: z
    .string()
    .trim()
    .min(3)
    .max(254)
    .refine((v) => v.includes('@'), 'Invalid email address'),
  reason: z.string().trim().min(5, 'A mandatory audit reason (min 5 chars) is required').max(500),
});

const createAdminUserSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(10).max(128),
  role: z.enum(['owner', 'admin', 'moderator', 'viewer']),
});

const updateAdminUserSchema = z
  .object({
    role: z.enum(['owner', 'admin', 'moderator', 'viewer']).optional(),
    status: z.enum(['active', 'disabled']).optional(),
  })
  .refine((v) => v.role !== undefined || v.status !== undefined, {
    message: 'role or status must be provided',
  });

const createDomainSchema = z.object({
  name: z
    .string()
    .trim()
    .toLowerCase()
    .min(3)
    .max(253)
    .regex(/^[a-z0-9.-]+\.[a-z]{2,}$/),
  active: z.boolean().optional(),
  notes: z.string().max(500).optional(),
});

const createBlocklistSchema = z.object({
  type: z.enum(['sender', 'domain', 'ip', 'keyword']),
  value: z.string().trim().min(1).max(320),
  reason: z.string().trim().max(500).optional(),
});

const updateSettingSchema = z.object({
  value: z.unknown().refine((v) => v !== undefined, 'value is required'),
});

const reservedNameSchema = z.object({
  name: z.string().trim().toLowerCase().min(1).max(64),
  reason: z.string().trim().max(200).optional().default('admin_reserved'),
});

const announcementSchema = z.object({
  title: z.string().trim().min(1).max(150),
  body: z.string().trim().min(1).max(2000),
  severity: z.enum(['info', 'warning', 'critical']).optional().default('info'),
  active: z.boolean().optional().default(false),
});

const updateAnnouncementSchema = z.object({
  title: z.string().trim().min(1).max(150).optional(),
  body: z.string().trim().min(1).max(2000).optional(),
  severity: z.enum(['info', 'warning', 'critical']).optional(),
  active: z.boolean().optional(),
});

const planChangeSchema = z.object({
  planId: z.enum(['free', 'premium']),
});

const idParamSchema = z.object({ id: z.string().trim().min(1).max(128) });
const numIdParamSchema = z.object({ id: z.coerce.number().int().min(1) });
const nameParamSchema = z.object({ name: z.string().trim().min(1).max(64) });
const addressParamSchema = z.object({
  address: z
    .string()
    .trim()
    .min(3)
    .max(254)
    .refine((v) => v.includes('@'), 'Invalid email address'),
});
const settingKeyParamSchema = z.object({
  key: z.string().trim().min(1).max(100).regex(/^[a-z0-9_]+$/),
});

interface AdminPendingMfa {
  readonly adminUserId: string;
  readonly setupRequired: boolean;
}

function formatAdminPublic(admin: AdminUserRecord) {
  return {
    id: admin.id,
    email: admin.email,
    role: admin.role,
    totpEnabled: admin.totpEnabled,
    status: admin.status,
    createdAt: admin.createdAt.toISOString(),
    lastLoginAt: admin.lastLoginAt ? admin.lastLoginAt.toISOString() : null,
  };
}

export async function registerAdminPanelRoutes(
  app: FastifyInstance,
  deps: AdminPanelRoutesDeps,
): Promise<void> {
  const {
    config,
    redis,
    logger,
    adminStore,
    adminPanelStore,
    accountInboxStore,
    mailer,
    ipAllowlist,
    onLiveSettingsMutated,
  } = deps;

  // Optional IP allowlist across all /admin/api/v1 endpoints
  if (ipAllowlist && ipAllowlist.length > 0) {
    app.addHook('onRequest', async (request) => {
      const normalizedIp = request.ip.replace(/^::ffff:/i, '');
      if (!ipAllowlist.includes(normalizedIp) && !ipAllowlist.includes(request.ip)) {
        throw new ApiError(403, 'ADMIN_IP_FORBIDDEN', 'IP address is not allowed for admin access');
      }
    });
  }

  const requireAdmin = async (
    request: FastifyRequest,
    permission: AdminPermission | null,
    requireCsrf: boolean,
  ): Promise<{ session: AdminSessionData; admin: AdminUserRecord }> => {
    if (requireCsrf && !hasValidCsrfHeader(request)) {
      throw new ApiError(403, 'CSRF_REQUIRED', 'Missing required CSRF protection header');
    }

    const sessionId = extractAdminSessionId(request, config.nodeEnv);
    if (!sessionId) {
      throw new ApiError(401, 'ADMIN_UNAUTHENTICATED', 'Admin authentication required');
    }

    const session = await getAdminSession(redis, sessionId);
    if (!session) {
      throw new ApiError(401, 'ADMIN_UNAUTHENTICATED', 'Admin session expired or invalid');
    }

    const admin = await adminPanelStore.findAdminById(session.adminUserId);
    if (!admin || admin.status !== 'active' || !admin.totpEnabled) {
      await destroyAdminSession(redis, sessionId, session.adminUserId);
      throw new ApiError(401, 'ADMIN_UNAUTHENTICATED', 'Admin account is not active or missing 2FA');
    }

    if (permission && !hasAdminPermission(admin.role, permission)) {
      throw new ApiError(
        403,
        'ADMIN_FORBIDDEN',
        `Role '${admin.role}' lacks permission '${permission}'`,
      );
    }

    return { session, admin };
  };

  const audit = async (
    admin: AdminUserRecord,
    request: FastifyRequest,
    action: string,
    target: string,
    details: Record<string, unknown> = {},
  ): Promise<void> => {
    await adminStore.insertAuditLog({
      actor: `${admin.role}:${admin.email}`,
      action,
      target,
      details: { ...details, ip: request.ip, adminUserId: admin.id },
    });
  };

  // --- Admin Auth (Mandatory 2FA, no self-registration) ---

  // POST /admin/api/v1/auth/login
  app.post(
    '/auth/login',
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: '15 minutes',
          keyGenerator: (request: FastifyRequest) => `rl:admin:login:${request.ip}`,
        },
      },
    },
    async (request) => {
      const body = adminLoginSchema.parse(request.body);
      const email = body.email.toLowerCase();
      const lockKey = `lock:admin:active:${hashToken(email)}`;
      const failKey = `lock:admin:fail:${hashToken(email)}`;

      if ((await redis.exists(lockKey)) === 1) {
        throw new ApiError(429, 'ADMIN_LOCKED', 'Too many failed admin login attempts');
      }

      const admin = await adminPanelStore.findAdminByEmail(email);
      if (!admin || admin.status !== 'active' || !(await verifyPassword(admin.passwordHash, body.password))) {
        const attempts = await redis.incr(failKey);
        if (attempts === 1) await redis.expire(failKey, ADMIN_LOCKOUT_SECONDS);
        if (attempts >= ADMIN_LOGIN_MAX_FAILURES) {
          await redis.set(lockKey, '1', 'EX', ADMIN_LOCKOUT_SECONDS);
        }
        throw new ApiError(401, 'INVALID_CREDENTIALS', 'Invalid admin credentials');
      }

      await redis.del(failKey, lockKey);

      if (!config.totpEncryptionKey) {
        throw new ApiError(503, 'TOTP_NOT_CONFIGURED', 'TOTP encryption key is not configured');
      }

      const { raw: mfaToken } = generateRandomToken();
      let setupPayload: { secret: string; otpauthUrl: string } | undefined;

      // Mandatory 2FA: if not yet enrolled, issue one-time enrollment challenge before granting a session
      if (!admin.totpEnabled || !admin.totpSecretEncrypted) {
        const enrollment = createTotpEnrollment(admin.email, 'TemporaMail Admin');
        const encrypted = encryptTotpSecret(enrollment.secret, config.totpEncryptionKey);
        await adminPanelStore.setAdminTotp(admin.id, encrypted, false);
        setupPayload = enrollment;
      }

      const pending: AdminPendingMfa = {
        adminUserId: admin.id,
        setupRequired: Boolean(setupPayload),
      };
      await redis.set(
        `admin:mfa:pending:${hashToken(mfaToken)}`,
        JSON.stringify(pending),
        'EX',
        ADMIN_MFA_PENDING_TTL_SECONDS,
      );

      return {
        mfaRequired: true,
        setupRequired: pending.setupRequired,
        mfaToken,
        ...(setupPayload ? { totpSetup: setupPayload } : {}),
      };
    },
  );

  // POST /admin/api/v1/auth/login/mfa
  app.post('/auth/login/mfa', async (request, reply) => {
    const body = adminMfaSchema.parse(request.body);
    const key = `admin:mfa:pending:${hashToken(body.mfaToken)}`;
    const rawPending = await redis.get(key);
    if (!rawPending) {
      throw new ApiError(401, 'INVALID_MFA_SESSION', 'Admin MFA challenge expired or invalid');
    }

    const pending = JSON.parse(rawPending) as AdminPendingMfa;
    const admin = await adminPanelStore.findAdminById(pending.adminUserId);
    if (!admin || admin.status !== 'active' || !admin.totpSecretEncrypted) {
      await redis.del(key);
      throw new ApiError(401, 'INVALID_MFA_SESSION', 'Admin account unavailable');
    }

    const secret = decryptTotpSecret(admin.totpSecretEncrypted, config.totpEncryptionKey);
    let verified = verifyTotpCode(secret, body.code);
    let recoveryCodesReturned: readonly string[] | undefined;

    if (!verified && !pending.setupRequired) {
      verified = await adminPanelStore.consumeAdminRecoveryCode(admin.id, hashRecoveryCode(body.code));
    }

    if (!verified) {
      throw new ApiError(401, 'INVALID_TOTP_CODE', 'Invalid admin 2FA code');
    }

    if (pending.setupRequired) {
      const { plainCodes, hashes } = generateRecoveryCodes(10);
      await adminPanelStore.setAdminTotp(admin.id, admin.totpSecretEncrypted, true, hashes);
      recoveryCodesReturned = plainCodes;
    }

    await redis.del(key);

    const session = await createAdminSession(redis, {
      adminUserId: admin.id,
      email: admin.email,
      role: admin.role,
      ip: request.ip,
    });
    setAdminSessionCookie(reply, config.nodeEnv, session);
    await adminPanelStore.updateAdminLastLogin(admin.id);
    await audit(admin, request, 'admin.login', admin.email, {
      setupCompleted: pending.setupRequired,
    });

    if (mailer) {
      void mailer
        .sendEmail(admin.email, 'admin_login_alert', {
          adminEmail: admin.email,
          ip: request.ip,
          reason: 'Successful admin login',
          time: new Date().toISOString(),
        })
        .catch((err) => logger.warn({ err }, 'Failed to send admin login alert'));
    }

    return {
      authenticated: true,
      admin: formatAdminPublic({ ...admin, totpEnabled: true }),
      ...(recoveryCodesReturned ? { recoveryCodes: recoveryCodesReturned } : {}),
    };
  });

  // POST /admin/api/v1/auth/logout
  app.post('/auth/logout', async (request, reply) => {
    const { session, admin } = await requireAdmin(request, null, true);
    await destroyAdminSession(redis, session.sessionId, admin.id);
    clearAdminSessionCookie(reply, config.nodeEnv);
    return { loggedOut: true };
  });

  // GET /admin/api/v1/auth/me
  app.get('/auth/me', async (request) => {
    const { admin } = await requireAdmin(request, null, false);
    return { admin: formatAdminPublic(admin) };
  });

  // --- Dashboard ---
  app.get('/dashboard', async (request) => {
    await requireAdmin(request, 'dashboard:read', false);
    const stats = await adminStore.getSmtpStatsLastHour();
    return {
      emailsLastHour: stats.emailsLastHour,
      rejectionsByReason: stats.rejectionsByReason,
      timestamp: new Date().toISOString(),
    };
  });

  // --- Domains ---
  app.get('/domains', async (request) => {
    await requireAdmin(request, 'domains:read', false);
    return { domains: await adminStore.listDomains() };
  });

  app.post('/domains', async (request, reply) => {
    const { admin } = await requireAdmin(request, 'domains:write', true);
    const body = createDomainSchema.parse(request.body);
    const created = await adminStore.createDomain({
      name: body.name,
      ...(body.active !== undefined ? { active: body.active } : {}),
      ...(body.notes !== undefined ? { notes: body.notes } : {}),
    });
    await audit(admin, request, 'domain.create', created.name, { id: created.id });
    if (onLiveSettingsMutated) await onLiveSettingsMutated();
    return reply.status(201).send(created);
  });

  // --- Blocklists ---
  app.get('/blocklist', async (request) => {
    await requireAdmin(request, 'blocklist:read', false);
    return { entries: await adminStore.listBlocklist() };
  });

  app.post('/blocklist', async (request, reply) => {
    const { admin } = await requireAdmin(request, 'blocklist:write', true);
    const body = createBlocklistSchema.parse(request.body);
    const created = await adminStore.addBlocklistEntry({
      type: body.type,
      value: body.value,
      ...(body.reason !== undefined ? { reason: body.reason } : {}),
    });
    await audit(admin, request, 'blocklist.add', `${created.type}:${created.value}`, {
      id: created.id,
      reason: created.reason,
    });
    if (onLiveSettingsMutated) await onLiveSettingsMutated();
    return reply.status(201).send(created);
  });

  app.delete('/blocklist/:id', async (request) => {
    const { admin } = await requireAdmin(request, 'blocklist:write', true);
    const { id } = numIdParamSchema.parse(request.params);
    const deleted = await adminStore.deleteBlocklistEntry(id);
    if (!deleted) throw new ApiError(404, 'BLOCKLIST_NOT_FOUND', 'Blocklist entry not found');
    await audit(admin, request, 'blocklist.delete', String(id));
    if (onLiveSettingsMutated) await onLiveSettingsMutated();
    return { deleted: true };
  });

  // --- Settings ---
  app.get('/settings', async (request) => {
    await requireAdmin(request, 'settings:read', false);
    return { settings: await adminStore.listSettings() };
  });

  app.put('/settings/:key', async (request) => {
    const { admin } = await requireAdmin(request, 'settings:write', true);
    const { key } = settingKeyParamSchema.parse(request.params);
    const { value } = updateSettingSchema.parse(request.body);
    const updated = await adminStore.upsertSetting(key, value);
    await audit(admin, request, 'settings.update', key, { value });
    if (onLiveSettingsMutated) await onLiveSettingsMutated();
    return updated;
  });

  // --- Inbox Lookup (Spec 7.3: owner/admin/moderator ONLY, mandatory reason, ALWAYS audit-logged) ---
  app.post('/inboxes/lookup', async (request) => {
    const { admin } = await requireAdmin(request, 'inboxes:lookup', true);
    const body = inboxLookupSchema.parse(request.body);
    const address = normalizeAddress(body.address);

    // Always audit-log the lookup with mandatory reason
    await audit(admin, request, 'inbox.lookup', address, { reason: body.reason });

    const redisInbox = await getInbox(redis, address);
    if (redisInbox) {
      const messages = await listInboxMessages(redis, address);
      return {
        store: 'redis_anonymous',
        address,
        expiresAt: new Date(redisInbox.expiresAt).toISOString(),
        messages,
      };
    }

    if (accountInboxStore) {
      const acctInbox = await accountInboxStore.findActiveInboxByAddress(address);
      if (acctInbox) {
        const messages = await accountInboxStore.listAccountMessages(acctInbox.id);
        return {
          store: 'postgres_account',
          address,
          userId: acctInbox.userId,
          expiresAt: acctInbox.expiresAt.toISOString(),
          messages,
        };
      }
    }

    throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox not found or expired');
  });

  // DELETE /admin/api/v1/inboxes/:address (abuse takedown)
  app.delete('/inboxes/:address', async (request) => {
    const { admin } = await requireAdmin(request, 'inboxes:delete', true);
    const { address: raw } = addressParamSchema.parse(request.params);
    const address = normalizeAddress(raw);

    const deletedRedis = await deleteInbox(redis, address);
    let deletedAccount = false;
    if (!deletedRedis && accountInboxStore) {
      const acct = await accountInboxStore.findActiveInboxByAddress(address);
      if (acct) {
        await accountInboxStore.deleteUserInbox(acct.userId, acct.id);
        await redis.del(`acct:inbox:${address}`);
        deletedAccount = true;
      }
    }

    if (!deletedRedis && !deletedAccount) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox not found');
    }

    await audit(admin, request, 'inbox.takedown', address);
    return { deleted: true, address };
  });

  // --- Users Management ---
  app.get('/users', async (request) => {
    await requireAdmin(request, 'users:read', false);
    const q = (request.query as { q?: string }).q;
    return { users: await adminPanelStore.searchUsers(q) };
  });

  app.post('/users/:id/ban', async (request) => {
    const { admin } = await requireAdmin(request, 'users:write', true);
    const { id } = idParamSchema.parse(request.params);
    const updated = await adminPanelStore.updateUserStatus(id, 'banned');
    if (!updated) throw new ApiError(404, 'USER_NOT_FOUND', 'User not found');

    // Banning immediately logs user out everywhere AND disables all API keys
    const sessionsDestroyed = await destroyAllUserSessions(redis, id);
    const keysRevoked = await adminPanelStore.disableAllApiKeysForUser(id);
    await audit(admin, request, 'user.ban', updated.email, {
      userId: id,
      sessionsDestroyed,
      keysRevoked,
    });

    return { user: updated, sessionsDestroyed, keysRevoked };
  });

  app.post('/users/:id/unban', async (request) => {
    const { admin } = await requireAdmin(request, 'users:write', true);
    const { id } = idParamSchema.parse(request.params);
    const updated = await adminPanelStore.updateUserStatus(id, 'active');
    if (!updated) throw new ApiError(404, 'USER_NOT_FOUND', 'User not found');
    await audit(admin, request, 'user.unban', updated.email, { userId: id });
    return { user: updated };
  });

  app.patch('/users/:id/plan', async (request) => {
    const { admin } = await requireAdmin(request, 'users:write', true);
    const { id } = idParamSchema.parse(request.params);
    const { planId } = planChangeSchema.parse(request.body);
    const updated = await adminPanelStore.updateUserPlan(id, planId);
    if (!updated) throw new ApiError(404, 'USER_NOT_FOUND', 'User not found');
    await audit(admin, request, 'user.change_plan', updated.email, { userId: id, planId });
    return { user: updated };
  });

  app.post('/users/:id/force-logout', async (request) => {
    const { admin } = await requireAdmin(request, 'users:write', true);
    const { id } = idParamSchema.parse(request.params);
    const count = await destroyAllUserSessions(redis, id);
    await audit(admin, request, 'user.force_logout', id, { sessionsDestroyed: count });
    return { sessionsDestroyed: count };
  });

  // --- API Keys Management ---
  app.get('/api-keys', async (request) => {
    await requireAdmin(request, 'apikeys:read', false);
    const prefix = (request.query as { prefix?: string }).prefix;
    return { apiKeys: await adminPanelStore.searchApiKeys(prefix) };
  });

  app.post('/api-keys/:id/disable', async (request) => {
    const { admin } = await requireAdmin(request, 'apikeys:write', true);
    const { id } = idParamSchema.parse(request.params);
    const disabled = await adminPanelStore.disableApiKeyById(id);
    if (!disabled) throw new ApiError(404, 'API_KEY_NOT_FOUND', 'Active API key not found');
    await audit(admin, request, 'api_key.disable', id);
    return { disabled: true };
  });

  // --- Reserved Names ---
  app.get('/reserved-names', async (request) => {
    await requireAdmin(request, 'reserved_names:read', false);
    return { reservedNames: await adminPanelStore.listReservedNames() };
  });

  app.post('/reserved-names', async (request, reply) => {
    const { admin } = await requireAdmin(request, 'reserved_names:write', true);
    const body = reservedNameSchema.parse(request.body);
    const created = await adminPanelStore.addReservedName(body.name, body.reason);
    await audit(admin, request, 'reserved_name.add', created.name, { reason: created.reason });
    return reply.status(201).send(created);
  });

  app.delete('/reserved-names/:name', async (request) => {
    const { admin } = await requireAdmin(request, 'reserved_names:write', true);
    const { name } = nameParamSchema.parse(request.params);
    const deleted = await adminPanelStore.deleteReservedName(name);
    if (!deleted) throw new ApiError(404, 'RESERVED_NAME_NOT_FOUND', 'Reserved name not found');
    await audit(admin, request, 'reserved_name.delete', name);
    return { deleted: true };
  });

  // --- Announcements ---
  app.get('/announcements', async (request) => {
    await requireAdmin(request, 'announcements:read', false);
    return { announcements: await adminPanelStore.listAnnouncements() };
  });

  app.post('/announcements', async (request, reply) => {
    const { admin } = await requireAdmin(request, 'announcements:write', true);
    const body = announcementSchema.parse(request.body);
    const created = await adminPanelStore.createAnnouncement(body);
    await audit(admin, request, 'announcement.create', String(created.id), {
      title: created.title,
      active: created.active,
    });
    return reply.status(201).send(created);
  });

  app.patch('/announcements/:id', async (request) => {
    const { admin } = await requireAdmin(request, 'announcements:write', true);
    const { id } = numIdParamSchema.parse(request.params);
    const body = updateAnnouncementSchema.parse(request.body);
    const updated = await adminPanelStore.updateAnnouncement(id, {
      ...(body.title !== undefined ? { title: body.title } : {}),
      ...(body.body !== undefined ? { body: body.body } : {}),
      ...(body.severity !== undefined ? { severity: body.severity } : {}),
      ...(body.active !== undefined ? { active: body.active } : {}),
    });
    if (!updated) throw new ApiError(404, 'ANNOUNCEMENT_NOT_FOUND', 'Announcement not found');
    await audit(admin, request, 'announcement.update', String(id), body);
    return updated;
  });

  // --- Admin Users Management (Owner Only) ---
  app.get('/admins', async (request) => {
    await requireAdmin(request, 'admins:manage', false);
    const list = await adminPanelStore.listAdminUsers();
    return { admins: list.map(formatAdminPublic) };
  });

  app.post('/admins', async (request, reply) => {
    const { admin } = await requireAdmin(request, 'admins:manage', true);
    const body = createAdminUserSchema.parse(request.body);
    const pwCheck = validatePasswordStrength(body.password);
    if (!pwCheck.valid) {
      throw new ApiError(400, 'WEAK_PASSWORD', pwCheck.reason ?? 'Password too weak');
    }
    const created = await adminPanelStore.createAdminUser({
      email: body.email,
      passwordHash: await hashPassword(body.password),
      role: body.role as AdminRole,
    });
    await audit(admin, request, 'admin_user.create', created.email, { role: created.role });
    return reply.status(201).send({ admin: formatAdminPublic(created) });
  });

  app.patch('/admins/:id', async (request) => {
    const { admin } = await requireAdmin(request, 'admins:manage', true);
    const { id } = idParamSchema.parse(request.params);
    const body = updateAdminUserSchema.parse(request.body);
    const updated = await adminPanelStore.updateAdminUser(id, {
      ...(body.role !== undefined ? { role: body.role } : {}),
      ...(body.status !== undefined ? { status: body.status } : {}),
    });
    if (!updated) throw new ApiError(404, 'ADMIN_NOT_FOUND', 'Admin user not found');
    if (body.status === 'disabled') {
      await destroyAllAdminSessions(redis, id);
    }
    await audit(admin, request, 'admin_user.update', updated.email, body);
    return { admin: formatAdminPublic(updated) };
  });

  app.post('/admins/:id/reset-2fa', async (request) => {
    const { admin } = await requireAdmin(request, 'admins:manage', true);
    const { id } = idParamSchema.parse(request.params);
    const ok = await adminPanelStore.resetAdminTotp(id);
    if (!ok) throw new ApiError(404, 'ADMIN_NOT_FOUND', 'Admin user not found');
    await destroyAllAdminSessions(redis, id);
    await audit(admin, request, 'admin_user.reset_2fa', id);
    return { reset: true };
  });

  // --- Audit Logs ---
  app.get('/audit-logs', async (request) => {
    await requireAdmin(request, 'audit:read', false);
    const limit = Number((request.query as { limit?: string }).limit) || 100;
    return { logs: await adminStore.listAuditLogs(limit) };
  });
}
