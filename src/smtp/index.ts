import { loadEnv } from '../config/env.js';
import { createRedisClient } from '../storage/redis.js';
import { createLogger } from '../utils/logger.js';
import { createSmtpServer } from './server.js';

async function main(): Promise<void> {
  const config = loadEnv();
  const logger = createLogger('smtp', config.logLevel, config.nodeEnv);
  const redis = createRedisClient(config.redisUrl);

  redis.on('error', (err) => {
    logger.error({ err }, 'Redis client error');
  });

  const server = createSmtpServer({
    config,
    redis,
    logger,
    hooks: {
      async onMessage(message) {
        logger.info(
          {
            sessionId: message.sessionId,
            remoteAddress: message.remoteAddress,
            mailFrom: message.mailFrom,
            rcptTo: message.rcptTo,
            bytes: message.raw.length,
          },
          'Accepted inbound SMTP message',
        );
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
