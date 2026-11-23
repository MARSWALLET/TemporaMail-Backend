import { loadEnv } from '../config/env.js';
import { createDbLiveSettingsLoader, LiveSettingsStore } from '../config/liveSettings.js';
import { processIncomingMessage } from '../pipeline/processMessage.js';
import { BlocklistStore } from '../protection/blocklist.js';
import { checkDnsbl } from '../protection/dnsbl.js';
import { checkSmtpIpRateLimit } from '../protection/ipLimiter.js';
import { createCompositeSpamChecker } from '../protection/spamChecker.js';
import { createDbAccountInboxStore } from '../storage/accountInboxStore.js';
import { createDbConnection, type DbConnection } from '../storage/db.js';
import { createRedisClient } from '../storage/redis.js';
import { insertSmtpLog } from '../storage/repositories.js';
import { createLogger } from '../utils/logger.js';
import { createSmtpServer } from './server.js';

async function main(): Promise<void> {
  const config = loadEnv();
  const logger = createLogger('smtp', config.logLevel, config.nodeEnv);
  const redis = createRedisClient(config.redisUrl);
  const blocklist = new BlocklistStore();

  redis.on('error', (err) => {
    logger.error({ err }, 'Redis client error');
  });

  let dbConn: DbConnection | undefined;
  let liveSettings: LiveSettingsStore;

  if (config.databaseUrl) {
    dbConn = createDbConnection(config.databaseUrl);
    liveSettings = new LiveSettingsStore({
      envConfig: config,
      logger,
      blocklist,
      loader: createDbLiveSettingsLoader(dbConn.db),
    });
    await liveSettings.refresh();
    liveSettings.start(60_000);
  } else {
    liveSettings = new LiveSettingsStore({
      envConfig: config,
      logger,
      blocklist,
    });
  }

  const recordSmtpLog = (entry: {
    ip: string;
    from: string;
    to: string;
    result: 'accepted' | 'rejected' | 'flagged';
    reason: string;
    spamScore: number;
  }): void => {
    if (!dbConn) {
      return;
    }
    void insertSmtpLog(dbConn.db, entry).catch((err) => {
      logger.warn({ err }, 'Failed to write smtp_log row');
    });
  };

  const spamChecker = createCompositeSpamChecker({
    logger,
    blocklist,
    getThresholds: () => {
      const snap = liveSettings.getSnapshot();
      return {
        rspamdUrl: config.rspamdUrl,
        rejectScore: snap.rspamdRejectScore,
        flagScore: snap.rspamdFlagScore,
      };
    },
  });

  const accountInboxStore = dbConn ? createDbAccountInboxStore(dbConn.db) : undefined;

  const server = createSmtpServer({
    config,
    redis,
    logger,
    hooks: {
      getAllowedDomains: () => liveSettings.getAllowedDomains(),
      ...(accountInboxStore
        ? {
            hasAccountInbox: async (address: string) =>
              (await accountInboxStore.findActiveInboxByAddress(address)) !== null,
          }
        : {}),
      async checkIpRateLimit(ip) {
        const snap = liveSettings.getSnapshot();
        const reason = await checkSmtpIpRateLimit(
          redis,
          ip,
          { maxSmtpMessagesPerMin: snap.smtpMaxMessagesPerMin },
          logger,
        );
        if (reason) {
          recordSmtpLog({ ip, from: '', to: '', result: 'rejected', reason, spamScore: 0 });
        }
        return reason;
      },
      async checkDnsbl(ip) {
        const ipBlocked = blocklist.checkIp(ip);
        if (ipBlocked.matched) {
          const reason = ipBlocked.reason ?? 'blocklist_ip';
          recordSmtpLog({ ip, from: '', to: '', result: 'rejected', reason, spamScore: 0 });
          return reason;
        }
        const dnsblReason = await checkDnsbl(
          redis,
          ip,
          {
            resolverIp: config.dnsResolver,
            zones: config.dnsblZones,
          },
          logger,
        );
        if (dnsblReason) {
          recordSmtpLog({
            ip,
            from: '',
            to: '',
            result: 'rejected',
            reason: dnsblReason,
            spamScore: 0,
          });
        }
        return dnsblReason;
      },
      async onMessage(message) {
        try {
          const outcome = await processIncomingMessage(message, {
            config,
            redis,
            logger,
            spamChecker,
            ...(accountInboxStore ? { accountInboxStore } : {}),
          });
          recordSmtpLog({
            ip: message.remoteAddress,
            from: message.mailFrom,
            to: message.rcptTo.join(','),
            result: outcome.spamFlagged ? 'flagged' : 'accepted',
            reason: outcome.spamFlagged ? 'spam_flagged' : '',
            spamScore: outcome.spamScore,
          });
        } catch (err) {
          const reason = err instanceof Error ? err.message : 'pipeline_error';
          recordSmtpLog({
            ip: message.remoteAddress,
            from: message.mailFrom,
            to: message.rcptTo.join(','),
            result: 'rejected',
            reason,
            spamScore: 0,
          });
          throw err;
        }
      },
    },
  });

  server.listen(config.smtpPort, () => {
    logger.info(
      {
        port: config.smtpPort,
        hostname: config.mailHostname,
        allowedDomains: liveSettings.getAllowedDomains(),
        tlsEnabled: Boolean(config.tlsKeyPath && config.tlsCertPath),
        postgresEnabled: Boolean(dbConn),
      },
      'TemporaMail SMTP server listening',
    );
  });

  const shutdown = (signal: string): void => {
    logger.info({ signal }, 'Shutting down SMTP server');
    liveSettings.stop();
    server.close(() => {
      void Promise.allSettled([redis.quit(), dbConn ? dbConn.close() : Promise.resolve()]).finally(
        () => {
          process.exit(0);
        },
      );
    });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

void main();
