CREATE TABLE IF NOT EXISTS "domains" (
  "id" serial PRIMARY KEY NOT NULL,
  "name" text NOT NULL,
  "active" boolean DEFAULT true NOT NULL,
  "notes" text DEFAULT '' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS "domains_name_uidx" ON "domains" ("name");

CREATE TABLE IF NOT EXISTS "blocklist" (
  "id" serial PRIMARY KEY NOT NULL,
  "type" text NOT NULL,
  "value" text NOT NULL,
  "reason" text DEFAULT '' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS "blocklist_type_value_uidx" ON "blocklist" ("type", "value");

CREATE TABLE IF NOT EXISTS "settings" (
  "key" text PRIMARY KEY NOT NULL,
  "value" jsonb NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS "abuse_reports" (
  "id" serial PRIMARY KEY NOT NULL,
  "address" text NOT NULL,
  "message_id" text,
  "reason" text NOT NULL,
  "reporter_ip" text NOT NULL,
  "status" text DEFAULT 'open' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "abuse_reports_status_idx" ON "abuse_reports" ("status");

CREATE TABLE IF NOT EXISTS "smtp_log" (
  "id" serial PRIMARY KEY NOT NULL,
  "time" timestamp with time zone DEFAULT now() NOT NULL,
  "ip" text NOT NULL,
  "from" text DEFAULT '' NOT NULL,
  "to" text DEFAULT '' NOT NULL,
  "result" text NOT NULL,
  "reason" text DEFAULT '' NOT NULL,
  "spam_score" real DEFAULT 0 NOT NULL
);

CREATE INDEX IF NOT EXISTS "smtp_log_time_idx" ON "smtp_log" ("time");
CREATE INDEX IF NOT EXISTS "smtp_log_ip_idx" ON "smtp_log" ("ip");
CREATE INDEX IF NOT EXISTS "smtp_log_result_idx" ON "smtp_log" ("result");

CREATE TABLE IF NOT EXISTS "audit_log" (
  "id" serial PRIMARY KEY NOT NULL,
  "actor" text NOT NULL,
  "action" text NOT NULL,
  "target" text NOT NULL,
  "details" jsonb DEFAULT '{}'::jsonb NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "audit_log_created_at_idx" ON "audit_log" ("created_at");
