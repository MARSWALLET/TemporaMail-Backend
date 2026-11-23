import { createHash, randomBytes } from 'node:crypto';

export const API_KEY_PREFIX = 'tm_live_';

export const ALL_API_KEY_SCOPES = [
  'inbox:create',
  'inbox:read',
  'inbox:delete',
  'messages:read',
] as const;

export type ApiKeyScope = (typeof ALL_API_KEY_SCOPES)[number];

const BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

export function encodeBase62(bytes: Buffer): string {
  let num = BigInt(`0x${bytes.toString('hex')}`);
  if (num === 0n) {
    return '0';
  }
  const base = 62n;
  let encoded = '';
  while (num > 0n) {
    const remainder = Number(num % base);
    encoded = (BASE62_ALPHABET[remainder] ?? '0') + encoded;
    num /= base;
  }
  return encoded;
}

export function hashApiKey(rawKey: string): string {
  return createHash('sha256').update(rawKey, 'utf8').digest('hex');
}

export interface GeneratedApiKey {
  readonly fullKey: string;
  readonly keyPrefix: string;
  readonly last4: string;
  readonly keyHash: string;
}

/**
 * Generates `tm_live_` + 32 random bytes encoded in base62.
 * Only `keyHash`, `keyPrefix`, and `last4` should be persisted.
 */
export function generateApiKey(): GeneratedApiKey {
  const tokenPart = encodeBase62(randomBytes(32));
  const fullKey = `${API_KEY_PREFIX}${tokenPart}`;
  const keyPrefix = fullKey.slice(0, API_KEY_PREFIX.length + 6);
  const last4 = fullKey.slice(-4);
  const keyHash = hashApiKey(fullKey);

  return {
    fullKey,
    keyPrefix,
    last4,
    keyHash,
  };
}

export function isApiKeyToken(token: string): boolean {
  return token.startsWith(API_KEY_PREFIX) && token.length >= API_KEY_PREFIX.length + 20;
}
