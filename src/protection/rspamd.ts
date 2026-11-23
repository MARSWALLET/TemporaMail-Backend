import type { Logger } from 'pino';

export interface RspamdOptions {
  readonly rspamdUrl: string;
  readonly rejectScore: number;
  readonly flagScore: number;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

export interface RspamdInput {
  readonly raw: Buffer;
  readonly ip: string;
  readonly mailFrom: string;
  readonly rcptTo: readonly string[];
}

export interface RspamdOutcome {
  readonly available: boolean;
  readonly score: number;
  readonly action: 'accept' | 'flag' | 'reject';
  readonly reason?: string;
}

interface RspamdResponseBody {
  readonly score?: number;
  readonly action?: string;
}

const DEFAULT_TIMEOUT_MS = 3000;

/**
 * Posts raw message bytes to Rspamd `/checkv2`.
 * Fails open if Rspamd is unreachable or times out.
 */
export async function checkRspamd(
  input: RspamdInput,
  options: RspamdOptions,
  logger: Logger,
): Promise<RspamdOutcome> {
  if (!options.rspamdUrl) {
    return { available: false, score: 0, action: 'accept' };
  }

  const fetchFn = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const endpoint = `${options.rspamdUrl.replace(/\/+$/, '')}/checkv2`;

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'text/plain',
      IP: input.ip,
      From: input.mailFrom,
    };
    const firstRcpt = input.rcptTo[0];
    if (firstRcpt) {
      headers.Rcpt = firstRcpt;
    }

    const response = await fetchFn(endpoint, {
      method: 'POST',
      headers,
      body: new Uint8Array(input.raw),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!response.ok) {
      logger.warn(
        { status: response.status, endpoint },
        'Rspamd returned non-OK status; failing open',
      );
      return { available: false, score: 0, action: 'accept' };
    }

    const data = (await response.json()) as RspamdResponseBody;
    const score = typeof data.score === 'number' && Number.isFinite(data.score) ? data.score : 0;

    if (score >= options.rejectScore) {
      logger.warn(
        { ip: input.ip, mailFrom: input.mailFrom, score, rejectScore: options.rejectScore },
        'Message rejected by Rspamd threshold',
      );
      return { available: true, score, action: 'reject', reason: 'rspamd_high_score' };
    }

    if (score >= options.flagScore) {
      return { available: true, score, action: 'flag', reason: 'rspamd_flagged' };
    }

    return { available: true, score, action: 'accept' };
  } catch (err) {
    logger.warn({ err, endpoint }, 'Rspamd request failed; failing open');
    return { available: false, score: 0, action: 'accept' };
  }
}
