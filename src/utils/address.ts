import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

/**
 * 32-character unambiguous lowercase alphanumeric alphabet.
 * Excludes 0/o and 1/l. Exact power of 2 eliminates modulo bias.
 */
export const SAFE_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';
export const MIN_LOCAL_PART_LENGTH = 10;
export const MAX_LOCAL_PART_LENGTH = 12;

export function generateLocalPart(length?: number): string {
  const targetLength = length ?? randomInt(MIN_LOCAL_PART_LENGTH, MAX_LOCAL_PART_LENGTH + 1);

  if (targetLength < MIN_LOCAL_PART_LENGTH || targetLength > MAX_LOCAL_PART_LENGTH) {
    throw new RangeError(
      `Local part length must be between ${MIN_LOCAL_PART_LENGTH} and ${MAX_LOCAL_PART_LENGTH}`,
    );
  }

  const bytes = randomBytes(targetLength);
  let result = '';

  for (let i = 0; i < targetLength; i += 1) {
    const byte = bytes[i];
    if (byte === undefined) {
      throw new Error('Failed to read random byte');
    }
    const char = SAFE_ALPHABET[byte & 31];
    if (char === undefined) {
      throw new Error('Failed to map random byte to alphabet');
    }
    result += char;
  }

  return result;
}

export function formatEmailAddress(localPart: string, domain: string): string {
  return `${localPart.trim().toLowerCase()}@${domain.trim().toLowerCase()}`;
}

export function normalizeAddress(address: string): string {
  return address.trim().toLowerCase();
}

export function extractDomain(address: string): string | null {
  const normalized = normalizeAddress(address);
  const atIndex = normalized.lastIndexOf('@');
  if (atIndex <= 0 || atIndex === normalized.length - 1) {
    return null;
  }
  return normalized.slice(atIndex + 1);
}

export function generateOwnerToken(): string {
  return randomBytes(32).toString('hex');
}

export function hashOwnerToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function verifyOwnerToken(token: string, expectedHash: string): boolean {
  const actualHash = hashOwnerToken(token);
  const actualBuf = Buffer.from(actualHash, 'hex');
  const expectedBuf = Buffer.from(expectedHash, 'hex');

  if (actualBuf.length !== expectedBuf.length) {
    return false;
  }

  return timingSafeEqual(actualBuf, expectedBuf);
}
