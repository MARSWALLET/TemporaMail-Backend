import type { Logger } from 'pino';

export interface TurnstileOptions {
  readonly secret: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

interface TurnstileVerifyResponse {
  readonly success?: boolean;
  readonly 'error-codes'?: readonly string[];
}

const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const DEFAULT_TIMEOUT_MS = 5000;

export async function verifyTurnstileToken(
  token: string,
  ip: string,
  options: TurnstileOptions,
  logger: Logger,
): Promise<boolean> {
  if (!options.secret || !token) {
    return false;
  }

  const fetchFn = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  try {
    const body = new URLSearchParams({
      secret: options.secret,
      response: token,
      remoteip: ip,
    });

    const response = await fetchFn(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!response.ok) {
      logger.warn({ status: response.status, ip }, 'Turnstile siteverify HTTP error');
      return false;
    }

    const data = (await response.json()) as TurnstileVerifyResponse;
    if (!data.success) {
      logger.warn(
        { ip, errorCodes: data['error-codes'] ?? [], reason: 'turnstile_failed' },
        'Turnstile verification rejected',
      );
      return false;
    }

    return true;
  } catch (err) {
    logger.error({ err, ip }, 'Turnstile verification request failed');
    return false;
  }
}
