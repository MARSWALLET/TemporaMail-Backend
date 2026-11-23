import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import type { EnvConfig } from '../config/env.js';
import type { AccountInboxStore } from '../storage/accountInboxStore.js';
import type { Database } from '../storage/db.js';
import { runDomainHealthCheck } from './domainHealth.js';
import { runRedisCleanup } from './redisCleanup.js';
import { runSmtpLogPurge } from './smtpLogPurge.js';

export interface MaintenanceSchedulerDeps {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly db?: Database;
  readonly accountInboxStore?: AccountInboxStore;
  readonly logger: Logger;
  readonly getAllowedDomains: () => readonly string[];
}

export interface MaintenanceSchedulerHandle {
  stop(): void;
}

const FIVE_MINUTES_MS = 5 * 60 * 1000;
const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

export function startMaintenanceJobs(
  deps: MaintenanceSchedulerDeps,
): MaintenanceSchedulerHandle {
  const { config, redis, db, accountInboxStore, logger, getAllowedDomains } = deps;
  const timers: Array<ReturnType<typeof setInterval>> = [];

  // Every 5 minutes: Redis orphan cleanup & expired account inbox cleanup
  const redisTimer = setInterval(() => {
    void runRedisCleanup(redis, logger).catch((err) => {
      logger.error({ err }, 'Redis cleanup job failed');
    });
    if (accountInboxStore) {
      void accountInboxStore.purgeExpired().catch((err) => {
        logger.error({ err }, 'Account inbox purge job failed');
      });
    }
  }, FIVE_MINUTES_MS);
  redisTimer.unref();
  timers.push(redisTimer);

  // Every 6 hours: purge smtp_log rows older than 7 days
  if (db) {
    const purgeTimer = setInterval(() => {
      void runSmtpLogPurge(db, logger, 7).catch((err) => {
        logger.error({ err }, 'SMTP log purge job failed');
      });
    }, SIX_HOURS_MS);
    purgeTimer.unref();
    timers.push(purgeTimer);
  }

  // Daily: domain MX, mail hostname DNS, and TLS cert expiry check
  const healthTimer = setInterval(() => {
    void runDomainHealthCheck(
      {
        mailHostname: config.mailHostname,
        domains: getAllowedDomains(),
        ...(config.tlsCertPath ? { tlsCertPath: config.tlsCertPath } : {}),
      },
      logger,
    ).catch((err) => {
      logger.error({ err }, 'Domain health check job failed');
    });
  }, TWENTY_FOUR_HOURS_MS);
  healthTimer.unref();
  timers.push(healthTimer);

  return {
    stop(): void {
      for (const timer of timers) {
        clearInterval(timer);
      }
      timers.length = 0;
    },
  };
}
