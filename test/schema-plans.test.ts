import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PLAN_LIMITS,
  getEntitlements,
  planLimitsSchema,
  type PlanLimits,
} from '../src/storage/plans.js';
import * as schema from '../src/storage/schema.js';

describe('Phase B2: Database schema, SQL migrations & entitlements', () => {
  it('exports all Phase A and Phase B Drizzle tables', () => {
    const requiredTables = [
      'domains',
      'blocklist',
      'settings',
      'abuseReports',
      'smtpLog',
      'auditLog',
      'plans',
      'users',
      'oauthAccounts',
      'emailTokens',
      'totpSecrets',
      'recoveryCodes',
      'sessions',
      'subscriptions',
      'userInboxes',
      'accountMessages',
      'apiKeys',
      'apiKeyUsageDaily',
      'reservedNames',
      'adminUsers',
      'adminRecoveryCodes',
      'announcements',
    ] as const;

    for (const table of requiredTables) {
      expect(schema[table]).toBeDefined();
    }
  });

  it('includes citext extension, all Phase B tables, and plan/reserved seeds in migration 0001', () => {
    const sqlPath = path.resolve(process.cwd(), 'drizzle', '0001_accounts_apikeys_admin.sql');
    const sql = readFileSync(sqlPath, 'utf8');

    expect(sql).toContain('CREATE EXTENSION IF NOT EXISTS citext');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "users"');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "oauth_accounts"');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "email_tokens"');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "totp_secrets"');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "recovery_codes"');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "user_inboxes"');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "account_messages"');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "api_keys"');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "api_key_usage_daily"');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "admin_users"');
    expect(sql).toContain("INSERT INTO \"plans\"");
    expect(sql).toContain("INSERT INTO \"reserved_names\"");
  });

  it('resolves entitlements for anonymous, free, premium, banned, and DB-overridden plans', () => {
    expect(planLimitsSchema.parse(DEFAULT_PLAN_LIMITS.anonymous)).toEqual(
      DEFAULT_PLAN_LIMITS.anonymous,
    );

    const anon = getEntitlements(null);
    expect(anon.planId).toBe('anonymous');
    expect(anon.maxInboxLifetimeMinutes).toBe(60);
    expect(anon.maxActiveAddresses).toBe(1);
    expect(anon.maxApiKeys).toBe(0);

    const free = getEntitlements({ planId: 'free', status: 'active' });
    expect(free.maxInboxLifetimeMinutes).toBe(1440);
    expect(free.maxActiveAddresses).toBe(3);
    expect(free.maxReservedCustomNames).toBe(1);
    expect(free.maxApiKeys).toBe(2);
    expect(free.apiRequestsPerDay).toBe(500);

    const premium = getEntitlements({ planId: 'premium', status: 'active' });
    expect(premium.maxActiveAddresses).toBe(20);
    expect(premium.apiRequestsPerDay).toBe(50_000);
    expect(premium.privateDomain).toBe(true);

    // Banned users are downgraded to anonymous limits
    const banned = getEntitlements({ planId: 'premium', status: 'banned' });
    expect(banned.planId).toBe('anonymous');
    expect(banned.maxApiKeys).toBe(0);

    // Dynamic DB override takes precedence
    const customPlans = new Map<string, PlanLimits>([
      [
        'free',
        {
          ...DEFAULT_PLAN_LIMITS.free,
          apiRequestsPerDay: 1000,
        },
      ],
    ]);
    const overridden = getEntitlements({ planId: 'free', status: 'active' }, customPlans);
    expect(overridden.apiRequestsPerDay).toBe(1000);
  });
});
