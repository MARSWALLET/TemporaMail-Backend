import { extractDomain } from '../utils/address.js';

const KNOWN_DISPOSABLE_DOMAINS: ReadonlySet<string> = new Set([
  '10minutemail.com',
  '10minutemail.net',
  'dispostable.com',
  'fakeinbox.com',
  'getnada.com',
  'guerrillamail.com',
  'guerrillamail.net',
  'guerrillamail.org',
  'maildrop.cc',
  'mailinator.com',
  'mailnesia.com',
  'mintemail.com',
  'mohmal.com',
  'sharklasers.com',
  'temp-mail.io',
  'temp-mail.org',
  'tempmail.com',
  'tempmail.net',
  'throwawaymail.com',
  'trashmail.com',
  'trashmail.net',
  'yopmail.com',
  'yopmail.fr',
  'yopmail.net',
]);

/**
 * Blocks disposable email providers AND our own temp domains during account signup.
 */
export function isDisposableEmail(
  email: string,
  ownTempDomains: readonly string[],
): boolean {
  const domain = extractDomain(email);
  if (!domain) {
    return true;
  }

  if (KNOWN_DISPOSABLE_DOMAINS.has(domain)) {
    return true;
  }

  for (const tempDomain of ownTempDomains) {
    const normalized = tempDomain.trim().toLowerCase();
    if (domain === normalized || domain.endsWith(`.${normalized}`)) {
      return true;
    }
  }

  return false;
}
