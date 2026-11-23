import { describe, expect, it } from 'vitest';
import {
  extractDomain,
  formatEmailAddress,
  generateLocalPart,
  generateOwnerToken,
  hashOwnerToken,
  MAX_LOCAL_PART_LENGTH,
  MIN_LOCAL_PART_LENGTH,
  SAFE_ALPHABET,
  verifyOwnerToken,
} from '../src/utils/address.js';

describe('address generator and token utilities', () => {
  it('generates local parts of length 10 to 12 using only the safe alphabet', () => {
    const allowedChars = new Set(SAFE_ALPHABET.split(''));
    const ambiguousChars = ['0', 'o', '1', 'l'];

    for (let i = 0; i < 200; i += 1) {
      const local = generateLocalPart();
      expect(local.length).toBeGreaterThanOrEqual(MIN_LOCAL_PART_LENGTH);
      expect(local.length).toBeLessThanOrEqual(MAX_LOCAL_PART_LENGTH);

      for (const ch of local) {
        expect(allowedChars.has(ch)).toBe(true);
        expect(ambiguousChars.includes(ch)).toBe(false);
      }
    }
  });

  it('generates unique local parts across a large batch', () => {
    const generated = new Set<string>();
    const count = 1000;
    for (let i = 0; i < count; i += 1) {
      generated.add(generateLocalPart());
    }
    expect(generated.size).toBe(count);
  });

  it('rejects out-of-range explicit lengths', () => {
    expect(() => generateLocalPart(9)).toThrow(RangeError);
    expect(() => generateLocalPart(13)).toThrow(RangeError);
  });

  it('formats and extracts domains consistently', () => {
    const addr = formatEmailAddress('AbCd234567', 'TemporaMail.APP');
    expect(addr).toBe('abcd234567@temporamail.app');
    expect(extractDomain(addr)).toBe('temporamail.app');
    expect(extractDomain('invalid-address')).toBeNull();
    expect(extractDomain('@temporamail.app')).toBeNull();
    expect(extractDomain('local@')).toBeNull();
  });

  it('generates 32-byte hex owner tokens and verifies hashes safely', () => {
    const token = generateOwnerToken();
    expect(token).toMatch(/^[0-9a-f]{64}$/);

    const hash = hashOwnerToken(token);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyOwnerToken(token, hash)).toBe(true);
    expect(verifyOwnerToken('wrong-token', hash)).toBe(false);
  });
});
