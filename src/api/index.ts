import { loadEnv } from '../config/env.js';
import { createDbLiveSettingsLoader, LiveSettingsStore } from '../config/liveSettings.js';
import { verifyTurnstileToken } from '../protection/turnstile.js';
import { createDbConnection, type DbConnection } from '../storage/db.js';
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

  let dbConn: DbConnection | undefined;
  let liveSettings: LiveSettingsStore;

  if (config.databaseUrl) {
    dbConn = createDbConnection(config.databaseUrl);
    liveSettings = new LiveSettingsStore({
      envConfig: config,
      logger,
      loader: createDbLiveSettingsLoader(dbConn.db),
    });
    await liveSettings.refresh();
    liveSettings.start(60_000);
  } else {
    liveSettings = new LiveSettingsStore({
      envConfig: config,
      logger,
    });
  }

  const app = await createApiApp({
    config,
    redis,
    logger,
    rateLimitRedis: redis,
    getAllowedDomains: () => liveSettings.getAllowedDomains(),
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
      allowedDomains: liveSettings.getAllowedDomains(),
      postgresEnabled: Boolean(dbConn),
    },
    'TemporaMail API server listening',
  );

  const shutdown = (signal: string): void => {
    logger.info({ signal }, 'Shutting down API server');
    liveSettings.stop();
    void app
      .close()
      .then(() => Promise.allSettled([redis.quit(), dbConn ? dbConn.close() : Promise.resolve()]))
      .finally(() => {
        process.exit(0);
      });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

void main();
