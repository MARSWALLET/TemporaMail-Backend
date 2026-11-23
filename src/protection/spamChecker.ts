import type { Logger } from 'pino';
import type { SpamChecker, SpamCheckInput, SpamCheckResult } from '../pipeline/types.js';
import type { BlocklistStore } from './blocklist.js';
import { verifyMailAuth, type AuthenticateFn } from './mailAuth.js';
import { checkRspamd } from './rspamd.js';

export interface CompositeSpamThresholds {
  readonly rspamdUrl: string;
  readonly rejectScore: number;
  readonly flagScore: number;
}

export interface CompositeSpamCheckerDeps {
  readonly logger: Logger;
  readonly blocklist: BlocklistStore;
  readonly getThresholds: () => CompositeSpamThresholds;
  readonly authenticateImpl?: AuthenticateFn;
  readonly fetchImpl?: typeof fetch;
}

/**
 * Combines Blocklists -> SPF/DKIM/DMARC (mailauth) -> Rspamd into a single SpamChecker.
 * No greylisting: OTP messages are evaluated immediately in real time.
 */
export function createCompositeSpamChecker(deps: CompositeSpamCheckerDeps): SpamChecker {
  const { logger, blocklist, getThresholds, authenticateImpl, fetchImpl } = deps;

  return async (input: SpamCheckInput): Promise<SpamCheckResult> => {
    // 1. Blocklist checks (IP, sender, domain, keyword)
    const blockMatch = blocklist.checkMessage({
      ip: input.remoteAddress,
      mailFrom: input.mailFrom,
      subject: input.subject,
      text: input.text,
    });

    if (blockMatch.matched) {
      const reason = blockMatch.reason ?? `blocklist_${blockMatch.type ?? 'match'}`;
      logger.warn(
        {
          ip: input.remoteAddress,
          mailFrom: input.mailFrom,
          type: blockMatch.type,
          value: blockMatch.value,
          reason,
        },
        'Message rejected by blocklist',
      );
      return {
        action: 'reject',
        score: 100,
        reason,
      };
    }

    // 2. SPF/DKIM/DMARC verification
    const authOutcome = await verifyMailAuth(
      {
        raw: input.raw,
        ip: input.remoteAddress,
        sender: input.mailFrom,
      },
      logger,
      authenticateImpl,
    );

    if (authOutcome.reject) {
      return {
        action: 'reject',
        score: authOutcome.scoreDelta,
        reason: authOutcome.reason ?? 'dmarc_policy_reject',
      };
    }

    // 3. Rspamd scoring (fails open if unavailable)
    const thresholds = getThresholds();
    const rspamdOutcome = await checkRspamd(
      {
        raw: input.raw,
        ip: input.remoteAddress,
        mailFrom: input.mailFrom,
        rcptTo: input.rcptTo,
      },
      {
        rspamdUrl: thresholds.rspamdUrl,
        rejectScore: thresholds.rejectScore,
        flagScore: thresholds.flagScore,
        ...(fetchImpl ? { fetchImpl } : {}),
      },
      logger,
    );

    const totalScore = Number((authOutcome.scoreDelta + rspamdOutcome.score).toFixed(2));

    if (rspamdOutcome.action === 'reject' || totalScore >= thresholds.rejectScore) {
      return {
        action: 'reject',
        score: totalScore,
        reason: rspamdOutcome.reason ?? 'spam_score_exceeded',
      };
    }

    if (rspamdOutcome.action === 'flag' || totalScore >= thresholds.flagScore) {
      return {
        action: 'flag',
        score: totalScore,
        reason: rspamdOutcome.reason ?? 'spam_score_flagged',
      };
    }

    return {
      action: 'accept',
      score: totalScore,
    };
  };
}
