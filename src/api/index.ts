import { loadEnv } from '../config/env.js';
import { createDbLiveSettingsLoader, LiveSettingsStore } from '../config/liveSettings.js';
import { startMaintenanceJobs } from '../jobs/scheduler.js';
import { createMailer } from '../mail/mailer.js';
import { verifyTurnstileToken } from '../protection/turnstile.js';
import { createDbAccountInboxStore } from '../storage/accountInboxStore.js';
import { createDbAdminPanelStore } from '../storage/adminPanelStore.js';
import { createDbAdminStore } from '../storage/adminStore.js';
import { createDbApiKeyStore } from '../storage/apiKeyStore.js';
import { createDbAuthStore } from '../storage/authStore.js';
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

  const mailer = createMailer({ config, logger });

  const accountInboxStore = dbConn ? createDbAccountInboxStore(dbConn.db) : undefined;

  const app = await createApiApp({
    config,
    redis,
    logger,
    rateLimitRedis: redis,
    mailer,
    getAllowedDomains: () => liveSettings.getAllowedDomains(),
    verifyTurnstile: (token, ip) =>
      verifyTurnstileToken(token, ip, { secret: config.turnstileSecret }, logger),
    ...(dbConn
      ? {
          adminStore: createDbAdminStore(dbConn.db),
          adminPanelStore: createDbAdminPanelStore(dbConn.db),
          authStore: createDbAuthStore(dbConn.db),
          apiKeyStore: createDbApiKeyStore(dbConn.db),
          ...(accountInboxStore ? { accountInboxStore } : {}),
          onLiveSettingsMutated: async () => {
            await liveSettings.refresh();
          },
        }
      : {}),
  });

  await app.listen({
    host: '0.0.0.0',
    port: config.apiPort,
  });

  const jobs = startMaintenanceJobs({
    config,
    redis,
    ...(dbConn ? { db: dbConn.db } : {}),
    ...(accountInboxStore ? { accountInboxStore } : {}),
    logger,
    getAllowedDomains: () => liveSettings.getAllowedDomains(),
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
    jobs.stop();
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
