import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { z } from 'zod';
import { verifyPassword } from '../../auth/password.js';
import {
  createUserSession,
  destroyUserSession,
  extractUserSessionId,
  getUserSession,
  hashToken,
  hasValidCsrfHeader,
  setUserSessionCookie,
  type UserSessionData,
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
import type { AuthStore, UserRecord } from '../../storage/authStore.js';
import { ApiError } from '../errors.js';

export interface TwoFactorRoutesDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  readonly authStore: AuthStore;
  readonly mailer: Mailer;
}

const MFA_MAX_ATTEMPTS = 5;
const TOTP_REPLAY_TTL_SECONDS = 90;

const enableSchema = z.object({
  code: z.string().trim().min(6).max(12),
});

const sensitiveTwoFaSchema = z.object({
  password: z.string().min(1).max(128).optional(),
  code: z.string().trim().min(6).max(20),
});

const loginMfaSchema = z.object({
  mfaToken: z.string().trim().min(16).max(256),
  code: z.string().trim().min(6).max(20),
});

interface PendingMfaState {
  readonly userId: string;
  readonly rememberMe: boolean;
  readonly ip: string;
}

async function verifyAndConsumeTotpOrRecovery(
  redis: Redis,
  authStore: AuthStore,
  userId: string,
  code: string,
  encryptionKey: string,
  allowRecoveryCode: boolean,
): Promise<'totp' | 'recovery' | null> {
  const encrypted = await authStore.getTotpSecret(userId);
  if (encrypted) {
    const secret = decryptTotpSecret(encrypted, encryptionKey);
    if (verifyTotpCode(secret, code)) {
      // Prevent TOTP code replay within the valid window
      const replayKey = `totp:used:${userId}:${hashToken(code.replace(/[\s-]+/g, ''))}`;
      const setRes = await redis.set(replayKey, '1', 'EX', TOTP_REPLAY_TTL_SECONDS, 'NX');
      if (setRes !== 'OK') {
        return null;
      }
      return 'totp';
    }
  }

  if (allowRecoveryCode) {
    const codeHash = hashRecoveryCode(code);
    const consumed = await authStore.consumeRecoveryCode(userId, codeHash);
    if (consumed) {
      return 'recovery';
    }
  }

  return null;
}

export async function registerTwoFactorRoutes(
  app: FastifyInstance,
  deps: TwoFactorRoutesDependencies,
): Promise<void> {
  const { config, redis, logger, authStore, mailer } = deps;

  const requireEncryptionKey = (): string => {
    if (!config.totpEncryptionKey) {
      throw new ApiError(503, 'TOTP_NOT_CONFIGURED', '2FA encryption key is not configured');
    }
    return config.totpEncryptionKey;
  };

  const requireAuth = async (
    request: FastifyRequest,
  ): Promise<{ session: UserSessionData; user: UserRecord }> => {
    if (!hasValidCsrfHeader(request)) {
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

  // POST /api/v1/account/2fa/setup
  app.post('/account/2fa/setup', async (request) => {
    const { user } = await requireAuth(request);
    if (user.totpEnabled) {
      throw new ApiError(409, 'TOTP_ALREADY_ENABLED', 'Two-factor authentication is already enabled');
    }

    const key = requireEncryptionKey();
    const { secret, otpauthUrl } = createTotpEnrollment(user.email, 'TemporaMail');
    const encrypted = encryptTotpSecret(secret, key);
    await authStore.setTotpSecret(user.id, encrypted);

    return {
      secret,
      otpauthUrl,
    };
  });

  // POST /api/v1/account/2fa/enable
  app.post('/account/2fa/enable', async (request, reply) => {
    const { session, user } = await requireAuth(request);
    if (user.totpEnabled) {
      throw new ApiError(409, 'TOTP_ALREADY_ENABLED', 'Two-factor authentication is already enabled');
    }

    const { code } = enableSchema.parse(request.body);
    const key = requireEncryptionKey();
    const encrypted = await authStore.getTotpSecret(user.id);
    if (!encrypted) {
      throw new ApiError(400, 'TOTP_SETUP_REQUIRED', 'Run 2FA setup before enabling');
    }

    const secret = decryptTotpSecret(encrypted, key);
    if (!verifyTotpCode(secret, code)) {
      throw new ApiError(400, 'INVALID_TOTP_CODE', 'Invalid authenticator code');
    }

    const { plainCodes, hashes } = generateRecoveryCodes(10);
    await authStore.enableTotp(user.id, hashes);

    // Rotate session on privilege/security state change
    await destroyUserSession(redis, session.sessionId, user.id);
    const rotated = await createUserSession(redis, {
      userId: user.id,
      ip: request.ip,
      userAgent: String(request.headers['user-agent'] ?? ''),
      rememberMe: session.rememberMe,
    });
    setUserSessionCookie(reply, config.nodeEnv, rotated);

    await mailer
      .sendEmail(user.email, '2fa_enabled', { time: new Date().toISOString() })
      .catch((err) => {
        logger.warn({ err, userId: user.id }, 'Failed to send 2fa_enabled email');
      });

    return {
      enabled: true,
      recoveryCodes: plainCodes,
    };
  });

  // POST /api/v1/account/2fa/disable
  app.post('/account/2fa/disable', async (request) => {
    const { user } = await requireAuth(request);
    if (!user.totpEnabled) {
      throw new ApiError(400, 'TOTP_NOT_ENABLED', 'Two-factor authentication is not enabled');
    }

    const body = sensitiveTwoFaSchema.parse(request.body);
    if (user.passwordHash) {
      if (!body.password || !(await verifyPassword(user.passwordHash, body.password))) {
        throw new ApiError(401, 'INVALID_CREDENTIALS', 'Password verification failed');
      }
    }

    const key = requireEncryptionKey();
    const method = await verifyAndConsumeTotpOrRecovery(
      redis,
      authStore,
      user.id,
      body.code,
      key,
      true,
    );
    if (!method) {
      throw new ApiError(400, 'INVALID_TOTP_CODE', 'Invalid 2FA or recovery code');
    }

    await authStore.disableTotp(user.id);

    await mailer
      .sendEmail(user.email, '2fa_changed', {
        action: 'Two-factor authentication disabled',
        time: new Date().toISOString(),
      })
      .catch((err) => {
        logger.warn({ err, userId: user.id }, 'Failed to send 2fa_changed email');
      });

    return { enabled: false };
  });

  // POST /api/v1/account/2fa/recovery-codes
  app.post('/account/2fa/recovery-codes', async (request) => {
    const { user } = await requireAuth(request);
    if (!user.totpEnabled) {
      throw new ApiError(400, 'TOTP_NOT_ENABLED', 'Two-factor authentication is not enabled');
    }

    const body = sensitiveTwoFaSchema.parse(request.body);
    if (user.passwordHash) {
      if (!body.password || !(await verifyPassword(user.passwordHash, body.password))) {
        throw new ApiError(401, 'INVALID_CREDENTIALS', 'Password verification failed');
      }
    }

    const key = requireEncryptionKey();
    const method = await verifyAndConsumeTotpOrRecovery(
      redis,
      authStore,
      user.id,
      body.code,
      key,
      false,
    );
    if (!method) {
      throw new ApiError(400, 'INVALID_TOTP_CODE', 'Valid authenticator code is required');
    }

    const { plainCodes, hashes } = generateRecoveryCodes(10);
    await authStore.replaceRecoveryCodes(user.id, hashes);

    await mailer
      .sendEmail(user.email, '2fa_changed', {
        action: 'Recovery codes regenerated',
        time: new Date().toISOString(),
      })
      .catch((err) => {
        logger.warn({ err, userId: user.id }, 'Failed to send 2fa_changed email');
      });

    return {
      recoveryCodes: plainCodes,
    };
  });

  // POST /api/v1/auth/login/mfa
  app.post(
    '/auth/login/mfa',
    {
      config: {
        rateLimit: {
          max: 15,
          timeWindow: '15 minutes',
          keyGenerator: (request: FastifyRequest) => `rl:auth:mfa:${request.ip}`,
        },
      },
    },
    async (request, reply) => {
      const body = loginMfaSchema.parse(request.body);
      const tokenHash = hashToken(body.mfaToken);
      const pendingKey = `mfa:pending:${tokenHash}`;
      const attemptsKey = `mfa:attempts:${tokenHash}`;

      const rawPending = await redis.get(pendingKey);
      if (!rawPending) {
        throw new ApiError(401, 'INVALID_MFA_SESSION', 'MFA challenge expired or invalid');
      }

      let pending: PendingMfaState;
      try {
        pending = JSON.parse(rawPending) as PendingMfaState;
      } catch {
        await redis.del(pendingKey);
        throw new ApiError(401, 'INVALID_MFA_SESSION', 'Invalid MFA challenge');
      }

      const user = await authStore.findUserById(pending.userId);
      if (!user || user.status !== 'active' || !user.totpEnabled) {
        await redis.del(pendingKey, attemptsKey);
        throw new ApiError(401, 'INVALID_MFA_SESSION', 'Account is not eligible for MFA');
      }

      const key = requireEncryptionKey();
      const method = await verifyAndConsumeTotpOrRecovery(
        redis,
        authStore,
        user.id,
        body.code,
        key,
        true,
      );

      if (!method) {
        const attempts = await redis.incr(attemptsKey);
        if (attempts === 1) {
          await redis.expire(attemptsKey, 300);
        }
        if (attempts >= MFA_MAX_ATTEMPTS) {
          await redis.del(pendingKey, attemptsKey);
          throw new ApiError(
            429,
            'MFA_TOO_MANY_ATTEMPTS',
            'Too many invalid 2FA codes. Please log in again.',
          );
        }
        throw new ApiError(401, 'INVALID_TOTP_CODE', 'Invalid 2FA or recovery code');
      }

      // Consume pending MFA challenge and create rotated session
      await redis.del(pendingKey, attemptsKey);

      const oldSessionId = extractUserSessionId(request, config.nodeEnv);
      if (oldSessionId) {
        await destroyUserSession(redis, oldSessionId);
      }

      const session = await createUserSession(redis, {
        userId: user.id,
        ip: request.ip,
        userAgent: String(request.headers['user-agent'] ?? ''),
        rememberMe: pending.rememberMe,
      });
      setUserSessionCookie(reply, config.nodeEnv, session);
      await authStore.updateLastLogin(user.id);

      await mailer
        .sendEmail(user.email, 'new_login_alert', {
          ip: request.ip,
          userAgent: String(request.headers['user-agent'] ?? 'Unknown'),
          time: new Date().toISOString(),
        })
        .catch((err) => {
          logger.warn({ err, userId: user.id }, 'Failed to send new login alert email');
        });

      return {
        authenticated: true,
        method,
        user: {
          id: user.id,
          email: user.email,
          emailVerified: user.emailVerifiedAt !== null,
          planId: user.planId,
          totpEnabled: user.totpEnabled,
        },
      };
    },
  );
}
