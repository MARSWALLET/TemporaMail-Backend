import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

export const GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
export const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
export const GOOGLE_JWKS_URL = new URL('https://www.googleapis.com/oauth2/v3/certs');

const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export interface PkcePair {
  readonly codeVerifier: string;
  readonly codeChallenge: string;
}

export interface VerifiedGoogleIdentity {
  readonly sub: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly nonce: string;
}

export interface GoogleOAuthClient {
  exchangeCode(input: {
    readonly code: string;
    readonly codeVerifier: string;
    readonly redirectUri: string;
  }): Promise<{ readonly idToken: string }>;
  verifyIdToken(idToken: string, expectedNonce: string): Promise<VerifiedGoogleIdentity>;
}

export function generatePkcePair(): PkcePair {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
  return { codeVerifier, codeChallenge };
}

export function buildGoogleAuthorizeUrl(params: {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly state: string;
  readonly nonce: string;
  readonly codeChallenge: string;
}): string {
  const url = new URL(GOOGLE_AUTH_ENDPOINT);
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', params.state);
  url.searchParams.set('nonce', params.nonce);
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('prompt', 'select_account');
  return url.toString();
}

function timingSafeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

export function createGoogleOAuthClient(options: {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly fetchImpl?: typeof fetch;
}): GoogleOAuthClient {
  const fetchFn = options.fetchImpl ?? fetch;
  const jwks = createRemoteJWKSet(GOOGLE_JWKS_URL);

  return {
    async exchangeCode({ code, codeVerifier, redirectUri }) {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: options.clientId,
        client_secret: options.clientSecret,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      });

      const response = await fetchFn(GOOGLE_TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
        signal: AbortSignal.timeout(8000),
      });

      if (!response.ok) {
        throw new Error(`Google token exchange failed with status ${response.status}`);
      }

      const data = (await response.json()) as { id_token?: string };
      if (!data.id_token || typeof data.id_token !== 'string') {
        throw new Error('Google token response missing id_token');
      }

      return { idToken: data.id_token };
    },

    async verifyIdToken(idToken, expectedNonce) {
      const { payload } = await jwtVerify(idToken, jwks, {
        audience: options.clientId,
        issuer: GOOGLE_ISSUERS,
      });

      const sub = typeof payload.sub === 'string' ? payload.sub : '';
      const email = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : '';
      const emailVerified = payload.email_verified === true;
      const nonce = typeof payload.nonce === 'string' ? payload.nonce : '';

      if (!sub || !email) {
        throw new Error('Google ID token missing required subject or email claim');
      }

      if (!nonce || !timingSafeStringEqual(nonce, expectedNonce)) {
        throw new Error('Google ID token nonce mismatch');
      }

      return {
        sub,
        email,
        emailVerified,
        nonce,
      };
    },
  };
}
