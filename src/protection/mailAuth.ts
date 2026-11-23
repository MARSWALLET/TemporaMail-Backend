import { authenticate } from 'mailauth';
import type { Logger } from 'pino';

export interface MailAuthInput {
  readonly raw: Buffer;
  readonly ip: string;
  readonly sender: string;
  readonly helo?: string;
}

export interface MailAuthOutcome {
  readonly reject: boolean;
  readonly reason?: string;
  readonly scoreDelta: number;
  readonly spfResult: string;
  readonly dkimResult: string;
  readonly dmarcResult: string;
  readonly dmarcPolicy: string | null;
}

interface MailAuthStatusShape {
  readonly result?: string;
}

interface MailAuthRawResult {
  readonly spf?: { readonly status?: MailAuthStatusShape } | false;
  readonly dkim?: { readonly results?: ReadonlyArray<{ readonly status?: MailAuthStatusShape }> };
  readonly dmarc?: {
    readonly status?: MailAuthStatusShape;
    readonly policy?: string;
  } | false;
}

export type AuthenticateFn = (
  message: Buffer,
  options: { ip?: string; helo?: string; sender?: string },
) => Promise<MailAuthRawResult>;

/**
 * Verifies SPF, DKIM, and DMARC using `mailauth`.
 * - Rejects on hard DMARC fail when the sender domain's policy is `reject`.
 * - Otherwise adds spam score penalties for SPF/DKIM/DMARC failures.
 * - Fails open if authentication checks throw unexpectedly.
 */
export async function verifyMailAuth(
  input: MailAuthInput,
  logger: Logger,
  authenticateImpl: AuthenticateFn = authenticate as unknown as AuthenticateFn,
): Promise<MailAuthOutcome> {
  try {
    const result = await authenticateImpl(input.raw, {
      ip: input.ip,
      sender: input.sender,
      ...(input.helo ? { helo: input.helo } : {}),
    });

    const spfResult =
      result.spf && result.spf.status?.result ? result.spf.status.result.toLowerCase() : 'none';

    const dkimResults = result.dkim?.results ?? [];
    const dkimPassed = dkimResults.some((r) => r.status?.result?.toLowerCase() === 'pass');
    const dkimFailed =
      !dkimPassed && dkimResults.some((r) => r.status?.result?.toLowerCase() === 'fail');
    const dkimResult = dkimPassed ? 'pass' : dkimFailed ? 'fail' : 'none';

    const dmarcResult =
      result.dmarc && result.dmarc.status?.result
        ? result.dmarc.status.result.toLowerCase()
        : 'none';
    const dmarcPolicy =
      result.dmarc && typeof result.dmarc.policy === 'string'
        ? result.dmarc.policy.toLowerCase()
        : null;

    if (dmarcResult === 'fail' && dmarcPolicy === 'reject') {
      logger.warn(
        {
          ip: input.ip,
          sender: input.sender,
          spfResult,
          dkimResult,
          dmarcResult,
          dmarcPolicy,
          reason: 'dmarc_policy_reject',
        },
        'Message rejected due to hard DMARC failure',
      );
      return {
        reject: true,
        reason: 'dmarc_policy_reject',
        scoreDelta: 10,
        spfResult,
        dkimResult,
        dmarcResult,
        dmarcPolicy,
      };
    }

    let scoreDelta = 0;
    if (spfResult === 'fail') {
      scoreDelta += 2;
    } else if (spfResult === 'softfail') {
      scoreDelta += 1;
    }

    if (dkimResult === 'fail') {
      scoreDelta += 1.5;
    }

    if (dmarcResult === 'fail') {
      scoreDelta += dmarcPolicy === 'quarantine' ? 3 : 1.5;
    }

    return {
      reject: false,
      scoreDelta,
      spfResult,
      dkimResult,
      dmarcResult,
      dmarcPolicy,
    };
  } catch (err) {
    logger.warn({ err, ip: input.ip, sender: input.sender }, 'mailauth failed; failing open');
    return {
      reject: false,
      scoreDelta: 0,
      spfResult: 'error',
      dkimResult: 'error',
      dmarcResult: 'error',
      dmarcPolicy: null,
    };
  }
}
