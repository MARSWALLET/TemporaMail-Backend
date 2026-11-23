import type { FastifyInstance } from 'fastify';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { z } from 'zod';
import {
  buildGoogleAuthorizeUrl,
  createGoogleOAuthClient,
  generatePkcePair,
  type GoogleOAuthClient,
} from '../../auth/googleOAuth.js';
import {
  createUserSession,
  destroyUserSession,
  extractUserSessionId,
  generateRandomToken,
  getUserSession,
  hashToken,
  hasValidCsrfHeader,
  setUserSessionCookie,
} from '../../auth/session.js';
import type { EnvConfig } from '../../config/env.js';
import type { AuthStore } from '../../storage/authStore.js';
import { ApiError } from '../errors.js';

export interface OAuthRoutesDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  readonly authStore: AuthStore;
  readonly googleClient?: GoogleOAuthClient;
}

const OAUTH_STATE_TTL_SECONDS = 600; // 10 minutes

const googleCallbackQuerySchema = z.object({
  code: z.string().trim().min(1).max(2048),
  state: z.string().trim().min(16).max(256),
});

interface StoredOAuthState {
  readonly nonce: string;
  readonly codeVerifier: string;
}

function oauthStateKey(stateHash: string): string {
  return `oauth:google:state:${stateHash}`;
}

export async function registerOAuthRoutes(
  app: FastifyInstance,
  deps: OAuthRoutesDependencies,
): Promise<void> {
  const { config, redis, logger, authStore } = deps;

  const getGoogleClient = (): GoogleOAuthClient => {
    if (deps.googleClient) {
      return deps.googleClient;
    }
    if (!config.googleClientId || !config.googleClientSecret) {
      throw new ApiError(503, 'OAUTH_NOT_CONFIGURED', 'Google sign-in is not configured');
    }
    return createGoogleOAuthClient({
      clientId: config.googleClientId,
      clientSecret: config.googleClientSecret,
    });
  };

  // GET /api/v1/auth/google
  app.get('/auth/google', async (_request, reply) => {
    if (!deps.googleClient && (!config.googleClientId || !config.googleClientSecret)) {
      throw new ApiError(503, 'OAUTH_NOT_CONFIGURED', 'Google sign-in is not configured');
    }

    const { raw: state, hash: stateHash } = generateRandomToken();
    const { raw: nonce } = generateRandomToken();
    const { codeVerifier, codeChallenge } = generatePkcePair();

    const stored: StoredOAuthState = { nonce, codeVerifier };
    await redis.set(
      oauthStateKey(stateHash),
      JSON.stringify(stored),
      'EX',
      OAUTH_STATE_TTL_SECONDS,
    );

    const authorizeUrl = buildGoogleAuthorizeUrl({
      clientId: config.googleClientId || 'test-client-id',
      redirectUri: config.googleRedirectUri,
      state,
      nonce,
      codeChallenge,
    });

    return reply.redirect(authorizeUrl, 302);
  });

  // GET /api/v1/auth/google/callback
  app.get('/auth/google/callback', async (request, reply) => {
    const query = googleCallbackQuerySchema.parse(request.query);
    const key = oauthStateKey(hashToken(query.state));
    const rawState = await redis.get(key);
    // Immediately consume state (single-use)
    await redis.del(key);

    if (!rawState) {
      throw new ApiError(400, 'INVALID_OAUTH_STATE', 'OAuth state is invalid or expired');
    }

    let parsedState: StoredOAuthState;
    try {
      parsedState = JSON.parse(rawState) as StoredOAuthState;
    } catch {
      throw new ApiError(400, 'INVALID_OAUTH_STATE', 'Corrupted OAuth state');
    }

    const googleClient = getGoogleClient();

    let idToken: string;
    try {
      const tokens = await googleClient.exchangeCode({
        code: query.code,
        codeVerifier: parsedState.codeVerifier,
        redirectUri: config.googleRedirectUri,
      });
      idToken = tokens.idToken;
    } catch (err) {
      logger.warn({ err }, 'Google OAuth code exchange failed');
      throw new ApiError(401, 'OAUTH_EXCHANGE_FAILED', 'Google authentication failed');
    }

    let identity;
    try {
      identity = await googleClient.verifyIdToken(idToken, parsedState.nonce);
    } catch (err) {
      logger.warn({ err }, 'Google ID token verification failed');
      throw new ApiError(401, 'INVALID_ID_TOKEN', 'Invalid Google identity token');
    }

    // Spec 2.3: Require email_verified: true from Google
    if (!identity.emailVerified) {
      throw new ApiError(
        403,
        'GOOGLE_EMAIL_UNVERIFIED',
        'Your Google account email must be verified to sign in',
      );
    }

    let user = null;
    const existingOAuth = await authStore.findOAuthAccount('google', identity.sub);

    if (existingOAuth) {
      user = await authStore.findUserById(existingOAuth.userId);
      if (!user || user.status !== 'active') {
        throw new ApiError(403, 'ACCOUNT_INACTIVE', 'Account is disabled or banned');
      }
    } else {
      const existingUserByEmail = await authStore.findUserByEmail(identity.email);
      if (existingUserByEmail) {
        if (existingUserByEmail.status !== 'active') {
          throw new ApiError(403, 'ACCOUNT_INACTIVE', 'Account is disabled or banned');
        }
        // Spec 2.3: Link only if existing account is email-verified (prevents pre-hijacking)
        if (!existingUserByEmail.emailVerifiedAt) {
          throw new ApiError(
            409,
            'ACCOUNT_UNVERIFIED_CONFLICT',
            'An unverified account with this email already exists. Verify your email before linking Google.',
          );
        }
        await authStore.linkOAuthAccount({
          userId: existingUserByEmail.id,
          provider: 'google',
          providerUserId: identity.sub,
          email: identity.email,
        });
        user = existingUserByEmail;
      } else {
        user = await authStore.createUser({
          email: identity.email,
          passwordHash: null,
          emailVerifiedAt: new Date(),
          planId: 'free',
        });
        await authStore.linkOAuthAccount({
          userId: user.id,
          provider: 'google',
          providerUserId: identity.sub,
          email: identity.email,
        });
      }
    }

    // Rotate any existing session cookie on OAuth login
    const oldSessionId = extractUserSessionId(request, config.nodeEnv);
    if (oldSessionId) {
      await destroyUserSession(redis, oldSessionId);
    }

    const session = await createUserSession(redis, {
      userId: user.id,
      ip: request.ip,
      userAgent: String(request.headers['user-agent'] ?? ''),
      rememberMe: true,
    });
    setUserSessionCookie(reply, config.nodeEnv, session);
    await authStore.updateLastLogin(user.id);

    const dashboardUrl = `${config.appBaseUrl.replace(/\/+$/, '')}/dashboard`;
    return reply.redirect(dashboardUrl, 302);
  });

  // DELETE /api/v1/account/oauth/google — unlink only if user has another login method (password)
  app.delete('/account/oauth/google', async (request) => {
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
      throw new ApiError(401, 'UNAUTHENTICATED', 'Account is not active');
    }

    if (!user.passwordHash) {
      throw new ApiError(
        400,
        'CANNOT_UNLINK_LAST_LOGIN_METHOD',
        'Set a password before unlinking your Google account',
      );
    }

    const unlinked = await authStore.unlinkOAuthAccount(user.id, 'google');
    if (!unlinked) {
      throw new ApiError(404, 'OAUTH_NOT_LINKED', 'Google account is not linked');
    }

    return { unlinked: true };
  });
}
