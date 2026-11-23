import type { Logger } from 'pino';
import { z } from 'zod';
import type { BlocklistEntry, BlocklistStore } from '../protection/blocklist.js';
import type { Database } from '../storage/db.js';
import {
  listActiveDomains,
  listBlocklistEntries,
  listSettings,
} from '../storage/repositories.js';
import type { EnvConfig } from './env.js';

export interface LiveSettingsSnapshot {
  readonly allowedDomains: readonly string[];
  readonly defaultTtlMinutes: number;
  readonly maxTtlMinutes: number;
  readonly maxMessageBytes: number;
  readonly maxMessagesPerInbox: number;
  readonly smtpMaxMessagesPerMin: number;
  readonly rspamdRejectScore: number;
  readonly rspamdFlagScore: number;
  readonly apiRateLimitPerMin: number;
  readonly inboxCreateLimitPerHour: number;
}

export interface LiveSettingsSourceData {
  readonly activeDomains: readonly string[];
  readonly blocklistEntries: readonly BlocklistEntry[];
  readonly settingsMap: ReadonlyMap<string, unknown>;
}

export type LiveSettingsLoader = () => Promise<LiveSettingsSourceData>;

const positiveInt = z.number().int().min(1);
const nonNegativeNum = z.number().min(0);

function readValidatedNumber(
  map: ReadonlyMap<string, unknown>,
  key: string,
  schema: z.ZodNumber,
  fallback: number,
): number {
  const raw = map.get(key);
  if (raw === undefined || raw === null) {
    return fallback;
  }
  const parsed = schema.safeParse(raw);
  return parsed.success ? parsed.data : fallback;
}

export function createDbLiveSettingsLoader(db: Database): LiveSettingsLoader {
  return async (): Promise<LiveSettingsSourceData> => {
    const [activeDomains, blocklistEntries, settingRows] = await Promise.all([
      listActiveDomains(db),
      listBlocklistEntries(db),
      listSettings(db),
    ]);

    const settingsMap = new Map<string, unknown>();
    for (const row of settingRows) {
      settingsMap.set(row.key, row.value);
    }

    return {
      activeDomains,
      blocklistEntries,
      settingsMap,
    };
  };
}

/**
 * Holds an in-memory snapshot of domains, blocklists, and tunable settings,
 * refreshed periodically from PostgreSQL without redeploying.
 */
export class LiveSettingsStore {
  private readonly envConfig: EnvConfig;
  private readonly logger: Logger;
  private readonly loader: LiveSettingsLoader | null;
  private readonly blocklist: BlocklistStore | undefined;
  private snapshot: LiveSettingsSnapshot;
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(deps: {
    readonly envConfig: EnvConfig;
    readonly logger: Logger;
    readonly loader?: LiveSettingsLoader;
    readonly blocklist?: BlocklistStore;
  }) {
    this.envConfig = deps.envConfig;
    this.logger = deps.logger;
    this.loader = deps.loader ?? null;
    this.blocklist = deps.blocklist;
    this.snapshot = this.buildDefaultSnapshot();
  }

  private buildDefaultSnapshot(): LiveSettingsSnapshot {
    return {
      allowedDomains: [...this.envConfig.allowedDomains],
      defaultTtlMinutes: this.envConfig.defaultTtlMinutes,
      maxTtlMinutes: this.envConfig.maxTtlMinutes,
      maxMessageBytes: this.envConfig.maxMessageBytes,
      maxMessagesPerInbox: this.envConfig.maxMessagesPerInbox,
      smtpMaxMessagesPerMin: this.envConfig.smtpMaxMessagesPerMin,
      rspamdRejectScore: this.envConfig.rspamdRejectScore,
      rspamdFlagScore: this.envConfig.rspamdFlagScore,
      apiRateLimitPerMin: this.envConfig.apiRateLimitPerMin,
      inboxCreateLimitPerHour: this.envConfig.inboxCreateLimitPerHour,
    };
  }

  getSnapshot(): LiveSettingsSnapshot {
    return this.snapshot;
  }

  getAllowedDomains(): readonly string[] {
    return this.snapshot.allowedDomains;
  }

  async refresh(): Promise<boolean> {
    if (!this.loader) {
      return false;
    }

    try {
      const data = await this.loader();
      const defaults = this.buildDefaultSnapshot();

      const allowedDomains =
        data.activeDomains.length > 0 ? [...data.activeDomains] : defaults.allowedDomains;

      const maxTtlMinutes = readValidatedNumber(
        data.settingsMap,
        'max_ttl_minutes',
        positiveInt,
        defaults.maxTtlMinutes,
      );
      const rawDefaultTtl = readValidatedNumber(
        data.settingsMap,
        'default_ttl_minutes',
        positiveInt,
        defaults.defaultTtlMinutes,
      );
      const defaultTtlMinutes = Math.min(rawDefaultTtl, maxTtlMinutes);

      this.snapshot = {
        allowedDomains,
        defaultTtlMinutes,
        maxTtlMinutes,
        maxMessageBytes: readValidatedNumber(
          data.settingsMap,
          'max_message_bytes',
          positiveInt,
          defaults.maxMessageBytes,
        ),
        maxMessagesPerInbox: readValidatedNumber(
          data.settingsMap,
          'max_messages_per_inbox',
          positiveInt,
          defaults.maxMessagesPerInbox,
        ),
        smtpMaxMessagesPerMin: readValidatedNumber(
          data.settingsMap,
          'smtp_max_messages_per_min',
          positiveInt,
          defaults.smtpMaxMessagesPerMin,
        ),
        rspamdRejectScore: readValidatedNumber(
          data.settingsMap,
          'rspamd_reject_score',
          nonNegativeNum,
          defaults.rspamdRejectScore,
        ),
        rspamdFlagScore: readValidatedNumber(
          data.settingsMap,
          'rspamd_flag_score',
          nonNegativeNum,
          defaults.rspamdFlagScore,
        ),
        apiRateLimitPerMin: readValidatedNumber(
          data.settingsMap,
          'api_rate_limit_per_min',
          positiveInt,
          defaults.apiRateLimitPerMin,
        ),
        inboxCreateLimitPerHour: readValidatedNumber(
          data.settingsMap,
          'inbox_create_limit_per_hour',
          positiveInt,
          defaults.inboxCreateLimitPerHour,
        ),
      };

      if (this.blocklist) {
        this.blocklist.update(data.blocklistEntries);
      }

      return true;
    } catch (err) {
      this.logger.warn({ err }, 'Live settings refresh failed; keeping last known snapshot');
      return false;
    }
  }

  start(intervalMs: number = 60_000): void {
    if (!this.loader || this.timer !== undefined) {
      return;
    }
    this.timer = setInterval(() => {
      void this.refresh();
    }, intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }
}
