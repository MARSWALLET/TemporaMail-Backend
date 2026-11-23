import { Resolver } from 'node:dns/promises';
import net from 'node:net';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';

export interface DnsblOptions {
  readonly resolverIp: string;
  readonly zones: readonly string[];
  readonly cacheTtlSeconds?: number;
  readonly timeoutMs?: number;
  /** Optional custom resolver function for testing. */
  readonly resolve4?: (hostname: string) => Promise<string[]>;
}

const DEFAULT_CACHE_TTL_SECONDS = 600; // 10 minutes
const DEFAULT_TIMEOUT_MS = 2000;

export function isPrivateOrLoopbackIp(ip: string): boolean {
  const normalized = ip.replace(/^::ffff:/i, '');
  if (
    normalized === '127.0.0.1' ||
    normalized === '::1' ||
    normalized === 'localhost' ||
    normalized.startsWith('10.') ||
    normalized.startsWith('192.168.') ||
    normalized.startsWith('169.254.') ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('fe80:')
  ) {
    return true;
  }

  if (normalized.startsWith('172.')) {
    const secondOctet = Number(normalized.split('.')[1]);
    if (secondOctet >= 16 && secondOctet <= 31) {
      return true;
    }
  }

  return false;
}

export function reverseIpv4(ip: string): string | null {
  const normalized = ip.replace(/^::ffff:/i, '');
  if (net.isIPv4(normalized) === false) {
    return null;
  }
  return normalized.split('.').reverse().join('.');
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('DNSBL_TIMEOUT'));
    }, timeoutMs);

    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

/**
 * Checks an IPv4 address against configured DNSBL zones with a 10-minute Redis cache.
 * Fails open on DNS errors or timeouts so legitimate mail is not dropped if DNS is unreachable.
 * Returns the matched DNSBL zone name if listed, or null if clean/skipped.
 */
export async function checkDnsbl(
  redis: Redis,
  ip: string,
  options: DnsblOptions,
  logger: Logger,
): Promise<string | null> {
  if (options.zones.length === 0 || isPrivateOrLoopbackIp(ip)) {
    return null;
  }

  const reversed = reverseIpv4(ip);
  if (!reversed) {
    return null;
  }

  const cacheKey = `dnsbl:${ip}`;
  try {
    const cached = await redis.get(cacheKey);
    if (cached !== null) {
      return cached === 'clean' ? null : cached;
    }
  } catch (err) {
    logger.warn({ err, ip }, 'DNSBL Redis cache read failed; continuing');
  }

  const cacheTtl = options.cacheTtlSeconds ?? DEFAULT_CACHE_TTL_SECONDS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let resolve4 = options.resolve4;
  if (!resolve4) {
    const resolver = new Resolver();
    if (options.resolverIp) {
      resolver.setServers([options.resolverIp]);
    }
    resolve4 = (hostname: string) => resolver.resolve4(hostname);
  }

  let matchedZone: string | null = null;
  let hadResolverError = false;

  for (const zone of options.zones) {
    const query = `${reversed}.${zone}`;
    try {
      const addresses = await withTimeout(resolve4(query), timeoutMs);
      if (addresses.length > 0) {
        matchedZone = `dnsbl:${zone}`;
        break;
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      // ENOTFOUND / ENODATA means the IP is NOT listed in this DNSBL
      if (code === 'ENOTFOUND' || code === 'ENODATA') {
        continue;
      }
      hadResolverError = true;
      logger.warn({ err, ip, zone }, 'DNSBL lookup error; failing open for zone');
    }
  }

  if (matchedZone) {
    await redis.set(cacheKey, matchedZone, 'EX', cacheTtl).catch(() => undefined);
    logger.warn({ ip, zone: matchedZone, reason: matchedZone }, 'IP listed in DNSBL');
    return matchedZone;
  }

  // Only cache clean result if lookups succeeded without transient DNS errors
  if (!hadResolverError) {
    await redis.set(cacheKey, 'clean', 'EX', cacheTtl).catch(() => undefined);
  }

  return null;
}
