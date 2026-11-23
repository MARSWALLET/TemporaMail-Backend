import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { z } from 'zod';
import { isDisposableEmail } from '../../auth/disposableDomains.js';
import {
  hashPassword,
  passwordNeedsRehash,
  validatePasswordStrength,
  verifyPassword,
} from '../../auth/password.js';
import {
  clearUserSessionCookie,
  createUserSession,
  destroyAllUserSessions,
  destroyUserSession,
  extractUserSessionId,
  generateRandomToken,
  getUserSession,
  hashToken,
  hasValidCsrfHeader,
  listUserSessions,
  setUserSessionCookie,
  type UserSessionData,
} from '../../auth/session.js';
import type { EnvConfig } from '../../config/env.js';
import type { Mailer } from '../../mail/mailer.js';
import type { AuthStore, UserRecord } from '../../storage/authStore.js';
import { getEntitlements } from '../../storage/plans.js';
import { ApiError } from '../errors.js';

export interface AuthRoutesDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  readonly authStore: AuthStore;
  readonly mailer: Mailer;
  readonly getAllowedDomains?: () => readonly string[];
  readonly verifyTurnstile?: (token: string, ip: string) => Promise<boolean>;
}

const VERIFY_TOKEN_TTL_HOURS = 24;
const RESET_TOKEN_TTL_MINUTES = 60;
const LOGIN_MAX_FAILURES = 5;
const LOGIN_LOCKOUT_SECONDS = 15 * 60;
const MFA_PENDING_TTL_SECONDS = 5 * 60;

const signupSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(128),
  turnstileToken: z.string().trim().min(1).optional(),
});

const loginSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(128),
  rememberMe: z.boolean().optional().default(false),
});

const verifyQuerySchema = z.object({
  token: z.string().trim().min(16).max(256),
});

const emailOnlySchema = z.object({
  email: z.string().trim().email().max(254),
});

const resetPasswordSchema = z.object({
  token: z.string().trim().min(16).max(256),
  newPassword: z.string().min(1).max(128),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: z.string().min(1).max(128),
});

const sessionIdParamSchema = z.object({
  id: z.string().trim().min(8).max(128),
});

const deleteAccountSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(128).optional(),
});

function sanitizeUserResponse(user: UserRecord) {
  return {
    id: user.id,
    email: user.email,
    emailVerified: user.emailVerifiedAt !== null,
    planId: user.planId,
    totpEnabled: user.totpEnabled,
    createdAt: user.createdAt.toISOString(),
    lastLoginAt: user.lastLoginAt ? user.lastLoginAt.toISOString() : null,
  };
}

function loginFailKey(email: string): string {
  return `lock:login:fail:${hashToken(email.trim().toLowerCase())}`;
}

function loginLockKey(email: string): string {
  return `lock:login:active:${hashToken(email.trim().toLowerCase())}`;
}

async function recordFailedLogin(redis: Redis, email: string): Promise<boolean> {
  const failKey = loginFailKey(email);
  const attempts = await redis.incr(failKey);
  if (attempts === 1) {
    await redis.expire(failKey, LOGIN_LOCKOUT_SECONDS);
  }
  if (attempts >= LOGIN_MAX_FAILURES) {
    await redis.set(loginLockKey(email), '1', 'EX', LOGIN_LOCKOUT_SECONDS);
    return true;
  }
  return false;
}

async function clearFailedLogins(redis: Redis, email: string): Promise<void> {
  await redis.del(loginFailKey(email), loginLockKey(email));
}

export async function registerAuthRoutes(
  app: FastifyInstance,
  deps: AuthRoutesDependencies,
): Promise<void> {
  const { config, redis, logger, authStore, mailer, getAllowedDomains, verifyTurnstile } = deps;

  const resolveOwnTempDomains = (): readonly string[] =>
    getAllowedDomains ? getAllowedDomains() : config.allowedDomains;

  const requireAuthenticatedSession = async (
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

  // POST /api/v1/auth/signup
  app.post(
    '/auth/signup',
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: '1 hour',
          keyGenerator: (request: FastifyRequest) => `rl:auth:signup:${request.ip}`,
        },
      },
    },
    async (request, reply) => {
      const body = signupSchema.parse(request.body);
      const email = body.email.toLowerCase();

      if (config.nodeEnv === 'production') {
        if (!body.turnstileToken) {
          throw new ApiError(400, 'CAPTCHA_REQUIRED', 'Turnstile verification token is required');
        }
        if (verifyTurnstile) {
          const ok = await verifyTurnstile(body.turnstileToken, request.ip);
          if (!ok) {
            throw new ApiError(403, 'CAPTCHA_FAILED', 'Turnstile verification failed');
          }
        }
      }

      if (isDisposableEmail(email, resolveOwnTempDomains())) {
        throw new ApiError(
          400,
          'DISPOSABLE_EMAIL_NOT_ALLOWED',
          'Disposable or temporary email addresses cannot be used to register an account',
        );
      }

      const pwCheck = validatePasswordStrength(body.password);
      if (!pwCheck.valid) {
        throw new ApiError(400, 'WEAK_PASSWORD', pwCheck.reason ?? 'Password is too weak');
      }

      const existing = await authStore.findUserByEmail(email);
      if (existing) {
        // Enumeration-safe generic response (do not reveal whether account exists)
        return reply.status(202).send({
          message: 'If this email is eligible, a verification link has been sent.',
        });
      }

      const passwordHash = await hashPassword(body.password);
      const user = await authStore.createUser({
        email,
        passwordHash,
        planId: 'free',
      });

      const { raw: verifyToken, hash: tokenHash } = generateRandomToken();
      await authStore.createEmailToken({
        userId: user.id,
        type: 'verify',
        tokenHash,
        expiresAt: new Date(Date.now() + VERIFY_TOKEN_TTL_HOURS * 60 * 60 * 1000),
      });

      const verifyUrl = `${config.appBaseUrl.replace(/\/+$/, '')}/verify?token=${encodeURIComponent(verifyToken)}`;
      await mailer
        .sendEmail(user.email, 'verify_email', {
          verifyUrl,
          expiresHours: VERIFY_TOKEN_TTL_HOURS,
        })
        .catch((err) => {
          logger.error({ err, userId: user.id }, 'Failed to send verification email');
        });

      return reply.status(202).send({
        message: 'If this email is eligible, a verification link has been sent.',
      });
    },
  );

  // GET /api/v1/auth/verify?token=...
  app.get('/auth/verify', async (request, reply) => {
    const { token } = verifyQuerySchema.parse(request.query);
    const tokenHash = hashToken(token);

    const consumed = await authStore.consumeEmailToken(tokenHash, 'verify');
    if (!consumed) {
      throw new ApiError(400, 'INVALID_TOKEN', 'Verification link is invalid or expired');
    }

    const user = await authStore.markEmailVerified(consumed.userId);
    if (!user || user.status !== 'active') {
      throw new ApiError(400, 'INVALID_TOKEN', 'Account cannot be verified');
    }

    const session = await createUserSession(redis, {
      userId: user.id,
      ip: request.ip,
      userAgent: String(request.headers['user-agent'] ?? ''),
      rememberMe: false,
    });
    setUserSessionCookie(reply, config.nodeEnv, session);

    return {
      verified: true,
      user: sanitizeUserResponse(user),
    };
  });

  // POST /api/v1/auth/resend-verification
  app.post(
    '/auth/resend-verification',
    {
      config: {
        rateLimit: {
          max: 5,
          timeWindow: '15 minutes',
          keyGenerator: (request: FastifyRequest) => `rl:auth:resend:${request.ip}`,
        },
      },
    },
    async (request) => {
      const { email } = emailOnlySchema.parse(request.body);
      const user = await authStore.findUserByEmail(email.toLowerCase());

      if (user && user.status === 'active' && !user.emailVerifiedAt) {
        const { raw: verifyToken, hash: tokenHash } = generateRandomToken();
        await authStore.createEmailToken({
          userId: user.id,
          type: 'verify',
          tokenHash,
          expiresAt: new Date(Date.now() + VERIFY_TOKEN_TTL_HOURS * 60 * 60 * 1000),
        });

        const verifyUrl = `${config.appBaseUrl.replace(/\/+$/, '')}/verify?token=${encodeURIComponent(verifyToken)}`;
        await mailer
          .sendEmail(user.email, 'verify_email', {
            verifyUrl,
            expiresHours: VERIFY_TOKEN_TTL_HOURS,
          })
          .catch((err) => {
            logger.error({ err, userId: user.id }, 'Failed to resend verification email');
          });
      }

      return {
        message: 'If that account requires verification, a new email has been sent.',
      };
    },
  );

  // POST /api/v1/auth/login
  app.post(
    '/auth/login',
    {
      config: {
        rateLimit: {
          max: 20,
          timeWindow: '15 minutes',
          keyGenerator: (request: FastifyRequest) => `rl:auth:login:${request.ip}`,
        },
      },
    },
    async (request, reply) => {
      const body = loginSchema.parse(request.body);
      const email = body.email.toLowerCase();

      const isLocked = (await redis.exists(loginLockKey(email))) === 1;
      if (isLocked) {
        throw new ApiError(
          429,
          'ACCOUNT_LOCKED',
          'Too many failed login attempts. Please try again in 15 minutes.',
        );
      }

      const user = await authStore.findUserByEmail(email);
      if (!user || !user.passwordHash || user.status !== 'active') {
        await recordFailedLogin(redis, email);
        throw new ApiError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
      }

      const validPassword = await verifyPassword(user.passwordHash, body.password);
      if (!validPassword) {
        const lockedNow = await recordFailedLogin(redis, email);
        if (lockedNow) {
          throw new ApiError(
            429,
            'ACCOUNT_LOCKED',
            'Too many failed login attempts. Please try again in 15 minutes.',
          );
        }
        throw new ApiError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
      }

      await clearFailedLogins(redis, email);

      // Transparent argon2id rehash if parameters changed
      if (passwordNeedsRehash(user.passwordHash)) {
        const upgradedHash = await hashPassword(body.password);
        await authStore.updatePasswordHash(user.id, upgradedHash);
      }

      // If 2FA is enabled, issue a short-lived MFA pending token instead of a full session
      if (user.totpEnabled) {
        const { raw: mfaToken } = generateRandomToken();
        await redis.set(
          `mfa:pending:${hashToken(mfaToken)}`,
          JSON.stringify({
            userId: user.id,
            rememberMe: body.rememberMe,
            ip: request.ip,
          }),
          'EX',
          MFA_PENDING_TTL_SECONDS,
        );
        return {
          mfaRequired: true,
          mfaToken,
        };
      }

      // Rotate any previous session cookie on login
      const oldSessionId = extractUserSessionId(request, config.nodeEnv);
      if (oldSessionId) {
        await destroyUserSession(redis, oldSessionId);
      }

      const session = await createUserSession(redis, {
        userId: user.id,
        ip: request.ip,
        userAgent: String(request.headers['user-agent'] ?? ''),
        rememberMe: body.rememberMe,
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
        mfaRequired: false,
        user: sanitizeUserResponse(user),
      };
    },
  );

  // POST /api/v1/auth/logout
  app.post('/auth/logout', async (request, reply) => {
    if (!hasValidCsrfHeader(request)) {
      throw new ApiError(403, 'CSRF_REQUIRED', 'Missing required CSRF protection header');
    }

    const sessionId = extractUserSessionId(request, config.nodeEnv);
    if (sessionId) {
      await destroyUserSession(redis, sessionId);
    }
    clearUserSessionCookie(reply, config.nodeEnv);
    return { loggedOut: true };
  });

  // POST /api/v1/auth/logout-all
  app.post('/auth/logout-all', async (request, reply) => {
    const { user } = await requireAuthenticatedSession(request, true);
    await destroyAllUserSessions(redis, user.id);
    clearUserSessionCookie(reply, config.nodeEnv);
    return { loggedOutAll: true };
  });

  // POST /api/v1/auth/forgot-password
  app.post(
    '/auth/forgot-password',
    {
      config: {
        rateLimit: {
          max: 5,
          timeWindow: '15 minutes',
          keyGenerator: (request: FastifyRequest) => `rl:auth:forgot:${request.ip}`,
        },
      },
    },
    async (request) => {
      const { email } = emailOnlySchema.parse(request.body);
      const user = await authStore.findUserByEmail(email.toLowerCase());

      if (user && user.status === 'active') {
        const { raw: resetToken, hash: tokenHash } = generateRandomToken();
        await authStore.createEmailToken({
          userId: user.id,
          type: 'reset',
          tokenHash,
          expiresAt: new Date(Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000),
        });

        const resetUrl = `${config.appBaseUrl.replace(/\/+$/, '')}/reset-password?token=${encodeURIComponent(resetToken)}`;
        await mailer
          .sendEmail(user.email, 'reset_password', {
            resetUrl,
            expiresMinutes: RESET_TOKEN_TTL_MINUTES,
          })
          .catch((err) => {
            logger.error({ err, userId: user.id }, 'Failed to send password reset email');
          });
      }

      return {
        message: 'If that account exists, we sent an email',
      };
    },
  );

  // POST /api/v1/auth/reset-password
  app.post('/auth/reset-password', async (request, reply) => {
    const body = resetPasswordSchema.parse(request.body);
    const pwCheck = validatePasswordStrength(body.newPassword);
    if (!pwCheck.valid) {
      throw new ApiError(400, 'WEAK_PASSWORD', pwCheck.reason ?? 'Password is too weak');
    }

    const tokenHash = hashToken(body.token);
    const consumed = await authStore.consumeEmailToken(tokenHash, 'reset');
    if (!consumed) {
      throw new ApiError(400, 'INVALID_TOKEN', 'Password reset link is invalid or expired');
    }

    const user = await authStore.findUserById(consumed.userId);
    if (!user || user.status !== 'active') {
      throw new ApiError(400, 'INVALID_TOKEN', 'Account is not active');
    }

    const nextHash = await hashPassword(body.newPassword);
    await authStore.updatePasswordHash(user.id, nextHash);
    // Invalidate ALL existing sessions after password reset
    await destroyAllUserSessions(redis, user.id);
    clearUserSessionCookie(reply, config.nodeEnv);

    await mailer
      .sendEmail(user.email, 'password_changed', { time: new Date().toISOString() })
      .catch((err) => {
        logger.warn({ err, userId: user.id }, 'Failed to send password changed email');
      });

    return { reset: true };
  });

  // GET /api/v1/account/me
  app.get('/account/me', async (request) => {
    const { user } = await requireAuthenticatedSession(request, false);
    const plansMap = await authStore.loadPlansMap();
    const entitlements = getEntitlements(user, plansMap);

    return {
      user: sanitizeUserResponse(user),
      entitlements,
    };
  });

  // POST /api/v1/account/password
  app.post('/account/password', async (request, reply) => {
    const { session, user } = await requireAuthenticatedSession(request, true);
    const body = changePasswordSchema.parse(request.body);

    if (user.passwordHash) {
      const matches = await verifyPassword(user.passwordHash, body.currentPassword);
      if (!matches) {
        throw new ApiError(401, 'INVALID_CREDENTIALS', 'Current password is incorrect');
      }
    }

    const pwCheck = validatePasswordStrength(body.newPassword);
    if (!pwCheck.valid) {
      throw new ApiError(400, 'WEAK_PASSWORD', pwCheck.reason ?? 'Password is too weak');
    }

    const nextHash = await hashPassword(body.newPassword);
    await authStore.updatePasswordHash(user.id, nextHash);

    // Rotate session ID on privilege/credential change
    await destroyUserSession(redis, session.sessionId, user.id);
    const rotated = await createUserSession(redis, {
      userId: user.id,
      ip: request.ip,
      userAgent: String(request.headers['user-agent'] ?? ''),
      rememberMe: session.rememberMe,
    });
    setUserSessionCookie(reply, config.nodeEnv, rotated);

    await mailer
      .sendEmail(user.email, 'password_changed', { time: new Date().toISOString() })
      .catch((err) => {
        logger.warn({ err, userId: user.id }, 'Failed to send password changed email');
      });

    return { updated: true };
  });

  // GET /api/v1/account/sessions
  app.get('/account/sessions', async (request) => {
    const { session, user } = await requireAuthenticatedSession(request, false);
    const allSessions = await listUserSessions(redis, user.id);

    return {
      sessions: allSessions.map((s) => ({
        id: s.sessionId,
        current: s.sessionId === session.sessionId,
        ip: s.ip,
        userAgent: s.userAgent,
        createdAt: new Date(s.createdAt).toISOString(),
        lastSeenAt: new Date(s.lastSeenAt).toISOString(),
      })),
    };
  });

  // DELETE /api/v1/account/sessions/:id
  app.delete('/account/sessions/:id', async (request) => {
    const { user } = await requireAuthenticatedSession(request, true);
    const { id } = sessionIdParamSchema.parse(request.params);

    const target = await getUserSession(redis, id, false);
    if (!target || target.userId !== user.id) {
      throw new ApiError(404, 'SESSION_NOT_FOUND', 'Session not found');
    }

    await destroyUserSession(redis, id, user.id);
    return { deleted: true };
  });

  // POST /api/v1/account/delete
  app.post('/account/delete', async (request, reply) => {
    const { user } = await requireAuthenticatedSession(request, true);
    const body = deleteAccountSchema.parse(request.body);

    if (body.email.toLowerCase() !== user.email.toLowerCase()) {
      throw new ApiError(400, 'EMAIL_MISMATCH', 'Confirmation email does not match your account');
    }

    if (user.passwordHash) {
      if (!body.password || !(await verifyPassword(user.passwordHash, body.password))) {
        throw new ApiError(401, 'INVALID_CREDENTIALS', 'Password verification failed');
      }
    }

    await destroyAllUserSessions(redis, user.id);
    await authStore.deleteUser(user.id);
    clearUserSessionCookie(reply, config.nodeEnv);

    return { deleted: true };
  });
}
