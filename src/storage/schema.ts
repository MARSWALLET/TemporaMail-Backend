import {
  boolean,
  index,
  jsonb,
  pgTable,
  real,
  serial,
  text,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core';

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
