import { loadEnv } from '../config/env.js';
import { processIncomingMessage } from '../pipeline/processMessage.js';
import { BlocklistStore } from '../protection/blocklist.js';
import { checkDnsbl } from '../protection/dnsbl.js';
import { checkSmtpIpRateLimit } from '../protection/ipLimiter.js';
import { createCompositeSpamChecker } from '../protection/spamChecker.js';
import { createRedisClient } from '../storage/redis.js';
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

  const spamChecker = createCompositeSpamChecker({
    logger,
    blocklist,
    getThresholds: () => ({
      rspamdUrl: config.rspamdUrl,
      rejectScore: config.rspamdRejectScore,
      flagScore: config.rspamdFlagScore,
    }),
  });

  const server = createSmtpServer({
    config,
    redis,
    logger,
    hooks: {
      async checkIpRateLimit(ip) {
        return checkSmtpIpRateLimit(
          redis,
          ip,
          { maxSmtpMessagesPerMin: config.smtpMaxMessagesPerMin },
          logger,
        );
      },
      async checkDnsbl(ip) {
        const ipBlocked = blocklist.checkIp(ip);
        if (ipBlocked.matched) {
          return ipBlocked.reason ?? 'blocklist_ip';
        }
        return checkDnsbl(
          redis,
          ip,
          {
            resolverIp: config.dnsResolver,
            zones: config.dnsblZones,
          },
          logger,
        );
      },
      async onMessage(message) {
        await processIncomingMessage(message, {
          config,
          redis,
          logger,
          spamChecker,
        });
      },
    },
  });

  server.listen(config.smtpPort, () => {
    logger.info(
      {
        port: config.smtpPort,
        hostname: config.mailHostname,
        allowedDomains: config.allowedDomains,
        tlsEnabled: Boolean(config.tlsKeyPath && config.tlsCertPath),
        dnsblZones: config.dnsblZones,
      },
      'TemporaMail SMTP server listening',
    );
  });

  const shutdown = (signal: string): void => {
    logger.info({ signal }, 'Shutting down SMTP server');
    server.close(() => {
      void redis.quit().finally(() => {
        process.exit(0);
      });
    });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

void main();
