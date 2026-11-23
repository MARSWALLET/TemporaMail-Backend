import { loadEnv } from '../config/env.js';
import { verifyTurnstileToken } from '../protection/turnstile.js';
import { createRedisClient } from '../storage/redis.js';
import { createLogger } from '../utils/logger.js';
import { createApiApp } from './app.js';

async function main(): Promise<void> {
  const config = loadEnv();
  const logger = createLogger('api', config.logLevel, config.nodeEnv);
  const redis = createRedisClient(config.redisUrl);

  redis.on('error', (err) => {
    logger.error({ err }, 'Redis client error');
  });

  const app = await createApiApp({
    config,
    redis,
    logger,
    rateLimitRedis: redis,
    verifyTurnstile: (token, ip) =>
      verifyTurnstileToken(token, ip, { secret: config.turnstileSecret }, logger),
  });

  await app.listen({
    host: '0.0.0.0',
    port: config.apiPort,
  });

  logger.info(
    {
      port: config.apiPort,
      corsOrigins: config.corsOrigins,
      allowedDomains: config.allowedDomains,
    },
    'TemporaMail API server listening',
  );

  const shutdown = (signal: string): void => {
    logger.info({ signal }, 'Shutting down API server');
    void app
      .close()
      .then(() => redis.quit())
      .finally(() => {
        process.exit(0);
      });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

void main();
