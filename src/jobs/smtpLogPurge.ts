import type { Logger } from 'pino';
import type { Database } from '../storage/db.js';
import { purgeOldSmtpLogs } from '../storage/repositories.js';

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

export async function runSmtpLogPurge(
  db: Database,
  logger: Logger,
  retentionDays: number = 7,
): Promise<number> {
  const cutoff = new Date(Date.now() - retentionDays * (SEVEN_DAYS_MS / 7));
  const deletedCount = await purgeOldSmtpLogs(db, cutoff);

  if (deletedCount > 0) {
    logger.info({ deletedCount, retentionDays }, 'Purged expired smtp_log rows');
  }

  return deletedCount;
}
