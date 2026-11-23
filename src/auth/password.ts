import argon2 from 'argon2';

export const MIN_PASSWORD_LENGTH = 10;
export const MAX_PASSWORD_LENGTH = 128;

export const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19_456, // 19 MiB (OWASP recommended minimum)
  timeCost: 2,
  parallelism: 1,
  raw: false,
} as const;

/**
 * Common weak passwords (case-insensitive) rejected regardless of length.
 */
const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  'password123',
  'password1234',
  'password12345',
  '1234567890',
  '12345678901',
  '123456789012',
  'qwerty12345',
  'qwertyuiop',
  'letmein1234',
  'welcome1234',
  'admin12345',
  'iloveyou123',
  'temporamail',
  'temporamail123',
  'aaaaaaaaaa',
  '0000000000',
  '1111111111',
  'abcdefghij',
  'changeme123',
  'passw0rd123',
]);

export interface PasswordValidationResult {
  readonly valid: boolean;
  readonly reason?: string;
}

export function validatePasswordStrength(password: string): PasswordValidationResult {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return {
      valid: false,
      reason: `Password must be at least ${MIN_PASSWORD_LENGTH} characters long`,
    };
  }

  if (password.length > MAX_PASSWORD_LENGTH) {
    return {
      valid: false,
      reason: `Password must be at most ${MAX_PASSWORD_LENGTH} characters long`,
    };
  }

  const normalized = password.trim().toLowerCase();
  if (COMMON_PASSWORDS.has(normalized)) {
    return {
      valid: false,
      reason: 'Password is too common; please choose a stronger passphrase',
    };
  }

  // Reject passwords consisting of a single repeated character
  if (new Set(password).size <= 2) {
    return {
      valid: false,
      reason: 'Password is too repetitive; please choose a stronger passphrase',
    };
  }

  return { valid: true };
}

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_OPTIONS);
}

/**
 * Precomputed valid argon2id hash used when verifying login for a non-existent account
 * so login latency stays constant and prevents timing-based email enumeration.
 */
const DUMMY_ARGON2ID_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZTEyMw$3q2+796tvu/er77v3q++796tvu/er77v3q++796tvu8';

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export async function verifyDummyPassword(password: string): Promise<void> {
  await verifyPassword(DUMMY_ARGON2ID_HASH, password);
}

export function passwordNeedsRehash(hash: string): boolean {
  return argon2.needsRehash(hash, ARGON2_OPTIONS);
}
