import { describe, expect, it } from 'vitest';
import { loadEnv } from '../src/config/env.js';
import { LiveSettingsStore } from '../src/config/liveSettings.js';
import { BlocklistStore } from '../src/protection/blocklist.js';
import { createLogger } from '../src/utils/logger.js';

const logger = createLogger('live-settings-test', 'silent', 'test');

describe('Step 6: LiveSettingsStore', () => {
  it('falls back to env defaults when no DB loader is provided', async () => {
    const envConfig = loadEnv({
      NODE_ENV: 'test',
      ALLOWED_DOMAINS: 'temporamail.app,alt.temporamail.app',
      DEFAULT_TTL_MINUTES: '10',
      MAX_TTL_MINUTES: '60',
      RSPAMD_REJECT_SCORE: '15',
      RSPAMD_FLAG_SCORE: '6',
    });

    const store = new LiveSettingsStore({ envConfig, logger });
    expect(await store.refresh()).toBe(false);
    expect(store.getAllowedDomains()).toEqual(['temporamail.app', 'alt.temporamail.app']);
    expect(store.getSnapshot()).toMatchObject({
      defaultTtlMinutes: 10,
      maxTtlMinutes: 60,
      rspamdRejectScore: 15,
      rspamdFlagScore: 6,
    });
  });

  it('refreshes domains, settings, and BlocklistStore from loader without redeploying', async () => {
    const envConfig = loadEnv({
      NODE_ENV: 'test',
      ALLOWED_DOMAINS: 'temporamail.app',
      DEFAULT_TTL_MINUTES: '10',
      MAX_TTL_MINUTES: '60',
    });
    const blocklist = new BlocklistStore();

    const store = new LiveSettingsStore({
      envConfig,
      logger,
      blocklist,
      loader: async () => ({
        activeDomains: ['temporamail.app', 'fresh.temporamail.app'],
        blocklistEntries: [
          { type: 'domain', value: 'spammer.example', reason: 'abuse' },
        ],
        settingsMap: new Map<string, unknown>([
          ['default_ttl_minutes', 20],
          ['max_ttl_minutes', 90],
          ['rspamd_reject_score', 12],
          ['rspamd_flag_score', 4.5],
          ['smtp_max_messages_per_min', 25],
          // Invalid value should safely fall back to env default
          ['max_messages_per_inbox', 'not-a-number'],
        ]),
      }),
    });

    const refreshed = await store.refresh();
    expect(refreshed).toBe(true);
    expect(store.getAllowedDomains()).toEqual(['temporamail.app', 'fresh.temporamail.app']);
    expect(store.getSnapshot()).toMatchObject({
      defaultTtlMinutes: 20,
      maxTtlMinutes: 90,
      rspamdRejectScore: 12,
      rspamdFlagScore: 4.5,
      smtpMaxMessagesPerMin: 25,
      maxMessagesPerInbox: 50,
    });

    expect(
      blocklist.checkMessage({
        ip: '198.51.100.1',
        mailFrom: 'x@spammer.example',
        subject: 'Hi',
        text: 'Body',
      }),
    ).toMatchObject({ matched: true, type: 'domain', reason: 'abuse' });
  });

  it('preserves last known good snapshot when DB refresh throws', async () => {
    const envConfig = loadEnv({ NODE_ENV: 'test', ALLOWED_DOMAINS: 'temporamail.app' });
    let shouldFail = false;

    const store = new LiveSettingsStore({
      envConfig,
      logger,
      loader: async () => {
        if (shouldFail) {
          throw new Error('PG connection reset');
        }
        return {
          activeDomains: ['custom.temporamail.app'],
          blocklistEntries: [],
          settingsMap: new Map<string, unknown>([['rspamd_reject_score', 11]]),
        };
      },
    });

    expect(await store.refresh()).toBe(true);
    expect(store.getAllowedDomains()).toEqual(['custom.temporamail.app']);

    shouldFail = true;
    expect(await store.refresh()).toBe(false);
    // Last known snapshot is retained
    expect(store.getAllowedDomains()).toEqual(['custom.temporamail.app']);
    expect(store.getSnapshot().rspamdRejectScore).toBe(11);
  });
});
