import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { generateSecret, generateSync, generateURI, verifySync } from 'otplib';

const RECOVERY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const RECOVERY_CODE_COUNT = 10;
const ENCRYPTION_PREFIX = 'v1';

function parseAesKey(hexKey: string): Buffer {
  if (!/^[0-9a-fA-F]{64}$/.test(hexKey)) {
    throw new Error('TOTP_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  }
  return Buffer.from(hexKey, 'hex');
}

/**
 * Encrypts a TOTP secret using AES-256-GCM with a fresh 12-byte IV.
 * Output format: `v1:{ivHex}:{authTagHex}:{ciphertextHex}`
 */
export function encryptTotpSecret(secret: string, hexKey: string): string {
  const key = parseAesKey(hexKey);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${ENCRYPTION_PREFIX}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

export function decryptTotpSecret(payload: string, hexKey: string): string {
  const key = parseAesKey(hexKey);
  const parts = payload.split(':');
  if (parts.length !== 4 || parts[0] !== ENCRYPTION_PREFIX) {
    throw new Error('Invalid encrypted TOTP payload format');
  }
  const [, ivHex, tagHex, dataHex] = parts;
  if (!ivHex || !tagHex || !dataHex) {
    throw new Error('Incomplete encrypted TOTP payload');
  }

  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataHex, 'hex')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

export function createTotpEnrollment(
  email: string,
  issuer: string = 'TemporaMail',
): { readonly secret: string; readonly otpauthUrl: string } {
  const secret = generateSecret();
  const otpauthUrl = generateURI({
    issuer,
    label: email,
    secret,
  });
  return { secret, otpauthUrl };
}

export function verifyTotpCode(secret: string, code: string): boolean {
  const normalized = code.replace(/[\s-]+/g, '');
  if (!/^\d{6}$/.test(normalized)) {
    return false;
  }
  try {
    const result = verifySync({
      secret,
      token: normalized,
      epochTolerance: 30,
    });
    return result.valid;
  } catch {
    return false;
  }
}

export function generateCurrentTotpCode(secret: string): string {
  return generateSync({ secret });
}

export function normalizeRecoveryCode(rawCode: string): string {
  return rawCode.replace(/[\s-]+/g, '').toUpperCase();
}

export function hashRecoveryCode(rawCode: string): string {
  return createHash('sha256').update(normalizeRecoveryCode(rawCode), 'utf8').digest('hex');
}

export function generateRecoveryCodes(count: number = RECOVERY_CODE_COUNT): {
  readonly plainCodes: readonly string[];
  readonly hashes: readonly string[];
} {
  const plainCodes: string[] = [];
  const hashes: string[] = [];

  for (let i = 0; i < count; i += 1) {
    const bytes = randomBytes(8);
    let raw = '';
    for (let j = 0; j < 8; j += 1) {
      const byte = bytes[j] ?? 0;
      const ch = RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length] ?? 'A';
      raw += ch;
    }
    const formatted = `${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
    plainCodes.push(formatted);
    hashes.push(hashRecoveryCode(formatted));
  }

  return { plainCodes, hashes };
}
