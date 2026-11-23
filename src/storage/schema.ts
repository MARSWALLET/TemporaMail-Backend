import {
  boolean,
  customType,
  date,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  real,
  serial,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

/**
 * Case-insensitive text column (`citext` extension in PostgreSQL).
 */
export const citext = customType<{ data: string }>({
  dataType() {
    return 'citext';
  },
});

// ============================================================================
// Phase A: Core Tables
// ============================================================================

export const domains = pgTable(
  'domains',
  {
    id: serial('id').primaryKey(),
    name: text('name').notNull(),
    active: boolean('active').notNull().default(true),
    notes: text('notes').notNull().default(''),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex('domains_name_uidx').on(table.name)],
);

export const blocklist = pgTable(
  'blocklist',
  {
    id: serial('id').primaryKey(),
    type: text('type').notNull(), // 'sender' | 'domain' | 'ip' | 'keyword'
    value: text('value').notNull(),
    reason: text('reason').notNull().default(''),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex('blocklist_type_value_uidx').on(table.type, table.value)],
);

export const settings = pgTable('settings', {
  key: text('key').primaryKey(),
  value: jsonb('value').notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const abuseReports = pgTable(
  'abuse_reports',
  {
    id: serial('id').primaryKey(),
    address: text('address').notNull(),
    messageId: text('message_id'),
    reason: text('reason').notNull(),
    reporterIp: text('reporter_ip').notNull(),
    status: text('status').notNull().default('open'), // 'open' | 'resolved' | 'dismissed'
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('abuse_reports_status_idx').on(table.status)],
);

export const smtpLog = pgTable(
  'smtp_log',
  {
    id: serial('id').primaryKey(),
    time: timestamp('time', { withTimezone: true }).notNull().defaultNow(),
    ip: text('ip').notNull(),
    from: text('from').notNull().default(''),
    to: text('to').notNull().default(''),
    result: text('result').notNull(), // 'accepted' | 'rejected' | 'flagged'
    reason: text('reason').notNull().default(''),
    spamScore: real('spam_score').notNull().default(0),
  },
  (table) => [
    index('smtp_log_time_idx').on(table.time),
    index('smtp_log_ip_idx').on(table.ip),
    index('smtp_log_result_idx').on(table.result),
  ],
);

export const auditLog = pgTable(
  'audit_log',
  {
    id: serial('id').primaryKey(),
    actor: text('actor').notNull(),
    action: text('action').notNull(),
    target: text('target').notNull(),
    details: jsonb('details').notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('audit_log_created_at_idx').on(table.createdAt)],
);

// ============================================================================
// Phase B: Accounts, Plans, Account Inboxes, API Keys & Admin Tables
// ============================================================================

export const plans = pgTable('plans', {
  id: text('id').primaryKey(), // 'anonymous' | 'free' | 'premium'
  name: text('name').notNull(),
  limits: jsonb('limits').notNull(),
});

export const users = pgTable(
  'users',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    email: citext('email').notNull(),
    passwordHash: text('password_hash'),
    emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),
    planId: text('plan_id')
      .notNull()
      .default('free')
      .references(() => plans.id),
    status: text('status').notNull().default('active'), // 'active' | 'banned' | 'deleted'
    totpEnabled: boolean('totp_enabled').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('users_email_uidx').on(table.email),
    index('users_status_idx').on(table.status),
  ],
);

export const oauthAccounts = pgTable(
  'oauth_accounts',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    provider: text('provider').notNull(), // 'google'
    providerUserId: text('provider_user_id').notNull(),
    email: citext('email').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('oauth_provider_user_uidx').on(table.provider, table.providerUserId),
    index('oauth_user_id_idx').on(table.userId),
  ],
);

export const emailTokens = pgTable(
  'email_tokens',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    type: text('type').notNull(), // 'verify' | 'reset' | 'change_email'
    targetEmail: citext('target_email'),
    tokenHash: text('token_hash').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('email_tokens_hash_uidx').on(table.tokenHash),
    index('email_tokens_user_type_idx').on(table.userId, table.type),
  ],
);

export const totpSecrets = pgTable('totp_secrets', {
  userId: uuid('user_id')
    .primaryKey()
    .references(() => users.id, { onDelete: 'cascade' }),
  secretEncrypted: text('secret_encrypted').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const recoveryCodes = pgTable(
  'recovery_codes',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    codeHash: text('code_hash').notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('recovery_codes_user_id_idx').on(table.userId)],
);

export const sessions = pgTable(
  'sessions',
  {
    id: text('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    ip: text('ip').notNull().default(''),
    userAgent: text('user_agent').notNull().default(''),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('sessions_user_id_idx').on(table.userId)],
);

export const subscriptions = pgTable(
  'subscriptions',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    planId: text('plan_id')
      .notNull()
      .references(() => plans.id),
    status: text('status').notNull().default('active'), // 'active' | 'canceled' | 'past_due'
    providerRef: text('provider_ref'),
    currentPeriodEnd: timestamp('current_period_end', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('subscriptions_user_id_idx').on(table.userId)],
);

export const userInboxes = pgTable(
  'user_inboxes',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    address: text('address').notNull(),
    customName: boolean('custom_name').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (table) => [
    uniqueIndex('user_inboxes_address_uidx').on(table.address),
    index('user_inboxes_user_id_idx').on(table.userId),
    index('user_inboxes_expires_at_idx').on(table.expiresAt),
  ],
);

export const accountMessages = pgTable(
  'account_messages',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    inboxId: uuid('inbox_id')
      .notNull()
      .references(() => userInboxes.id, { onDelete: 'cascade' }),
    body: jsonb('body').notNull(),
    attachments: jsonb('attachments').notNull().default([]),
    receivedAt: timestamp('received_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (table) => [
    index('account_messages_inbox_id_idx').on(table.inboxId),
    index('account_messages_expires_at_idx').on(table.expiresAt),
  ],
);

export const apiKeys = pgTable(
  'api_keys',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    keyPrefix: text('key_prefix').notNull(),
    last4: text('last4').notNull(),
    keyHash: text('key_hash').notNull(),
    scopes: text('scopes').array().notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    lastIp: text('last_ip'),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('api_keys_hash_uidx').on(table.keyHash),
    index('api_keys_user_id_idx').on(table.userId),
  ],
);

export const apiKeyUsageDaily = pgTable(
  'api_key_usage_daily',
  {
    apiKeyId: uuid('api_key_id')
      .notNull()
      .references(() => apiKeys.id, { onDelete: 'cascade' }),
    day: date('day').notNull(),
    count: integer('count').notNull().default(0),
  },
  (table) => [primaryKey({ columns: [table.apiKeyId, table.day] })],
);

export const reservedNames = pgTable('reserved_names', {
  name: text('name').primaryKey(),
  reason: text('reason').notNull().default('reserved'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const adminUsers = pgTable(
  'admin_users',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    email: citext('email').notNull(),
    passwordHash: text('password_hash').notNull(),
    role: text('role').notNull().default('viewer'), // 'owner' | 'admin' | 'moderator' | 'viewer'
    totpSecretEncrypted: text('totp_secret_encrypted'),
    totpEnabled: boolean('totp_enabled').notNull().default(false),
    status: text('status').notNull().default('active'), // 'active' | 'disabled'
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
  },
  (table) => [uniqueIndex('admin_users_email_uidx').on(table.email)],
);

export const adminRecoveryCodes = pgTable(
  'admin_recovery_codes',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    adminUserId: uuid('admin_user_id')
      .notNull()
      .references(() => adminUsers.id, { onDelete: 'cascade' }),
    codeHash: text('code_hash').notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('admin_recovery_codes_admin_id_idx').on(table.adminUserId)],
);

export const announcements = pgTable(
  'announcements',
  {
    id: serial('id').primaryKey(),
    title: text('title').notNull(),
    body: text('body').notNull(),
    severity: text('severity').notNull().default('info'), // 'info' | 'warning' | 'critical'
    active: boolean('active').notNull().default(false),
    startsAt: timestamp('starts_at', { withTimezone: true }),
    endsAt: timestamp('ends_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('announcements_active_idx').on(table.active)],
);
