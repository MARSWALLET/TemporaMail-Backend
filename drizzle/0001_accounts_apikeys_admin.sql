CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Plans
CREATE TABLE IF NOT EXISTS "plans" (
  "id" text PRIMARY KEY NOT NULL,
  "name" text NOT NULL,
  "limits" jsonb NOT NULL
);

INSERT INTO "plans" ("id", "name", "limits") VALUES
  ('anonymous', 'Anonymous', '{"maxInboxLifetimeMinutes":60,"maxActiveAddresses":1,"maxReservedCustomNames":0,"maxApiKeys":0,"apiRequestsPerDay":0,"maxAttachmentBytes":2097152,"privateDomain":false}'::jsonb),
  ('free', 'Free', '{"maxInboxLifetimeMinutes":1440,"maxActiveAddresses":3,"maxReservedCustomNames":1,"maxApiKeys":2,"apiRequestsPerDay":500,"maxAttachmentBytes":5242880,"privateDomain":false}'::jsonb),
  ('premium', 'Premium', '{"maxInboxLifetimeMinutes":43200,"maxActiveAddresses":20,"maxReservedCustomNames":10,"maxApiKeys":10,"apiRequestsPerDay":50000,"maxAttachmentBytes":10485760,"privateDomain":true}'::jsonb)
ON CONFLICT ("id") DO NOTHING;

-- Users
CREATE TABLE IF NOT EXISTS "users" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "email" citext NOT NULL,
  "password_hash" text,
  "email_verified_at" timestamp with time zone,
  "plan_id" text DEFAULT 'free' NOT NULL REFERENCES "plans" ("id"),
  "status" text DEFAULT 'active' NOT NULL,
  "totp_enabled" boolean DEFAULT false NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "last_login_at" timestamp with time zone
);

CREATE UNIQUE INDEX IF NOT EXISTS "users_email_uidx" ON "users" ("email");
CREATE INDEX IF NOT EXISTS "users_status_idx" ON "users" ("status");

-- OAuth Accounts
CREATE TABLE IF NOT EXISTS "oauth_accounts" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "provider" text NOT NULL,
  "provider_user_id" text NOT NULL,
  "email" citext NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS "oauth_provider_user_uidx" ON "oauth_accounts" ("provider", "provider_user_id");
CREATE INDEX IF NOT EXISTS "oauth_user_id_idx" ON "oauth_accounts" ("user_id");

-- Email Tokens (verify, reset, change_email)
CREATE TABLE IF NOT EXISTS "email_tokens" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "type" text NOT NULL,
  "target_email" citext,
  "token_hash" text NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "used_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS "email_tokens_hash_uidx" ON "email_tokens" ("token_hash");
CREATE INDEX IF NOT EXISTS "email_tokens_user_type_idx" ON "email_tokens" ("user_id", "type");

-- User 2FA
CREATE TABLE IF NOT EXISTS "totp_secrets" (
  "user_id" uuid PRIMARY KEY NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "secret_encrypted" text NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS "recovery_codes" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "code_hash" text NOT NULL,
  "used_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "recovery_codes_user_id_idx" ON "recovery_codes" ("user_id");

-- Session Metadata (session state lives in Redis)
CREATE TABLE IF NOT EXISTS "sessions" (
  "id" text PRIMARY KEY NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "ip" text DEFAULT '' NOT NULL,
  "user_agent" text DEFAULT '' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "sessions_user_id_idx" ON "sessions" ("user_id");

-- Subscriptions
CREATE TABLE IF NOT EXISTS "subscriptions" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "plan_id" text NOT NULL REFERENCES "plans" ("id"),
  "status" text DEFAULT 'active' NOT NULL,
  "provider_ref" text,
  "current_period_end" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "subscriptions_user_id_idx" ON "subscriptions" ("user_id");

-- Account-owned Inboxes & Messages
CREATE TABLE IF NOT EXISTS "user_inboxes" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "address" text NOT NULL,
  "custom_name" boolean DEFAULT false NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "expires_at" timestamp with time zone NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS "user_inboxes_address_uidx" ON "user_inboxes" ("address");
CREATE INDEX IF NOT EXISTS "user_inboxes_user_id_idx" ON "user_inboxes" ("user_id");
CREATE INDEX IF NOT EXISTS "user_inboxes_expires_at_idx" ON "user_inboxes" ("expires_at");

CREATE TABLE IF NOT EXISTS "account_messages" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "inbox_id" uuid NOT NULL REFERENCES "user_inboxes" ("id") ON DELETE CASCADE,
  "body" jsonb NOT NULL,
  "attachments" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "received_at" timestamp with time zone DEFAULT now() NOT NULL,
  "expires_at" timestamp with time zone NOT NULL
);

CREATE INDEX IF NOT EXISTS "account_messages_inbox_id_idx" ON "account_messages" ("inbox_id");
CREATE INDEX IF NOT EXISTS "account_messages_expires_at_idx" ON "account_messages" ("expires_at");

-- API Keys & Daily Usage
CREATE TABLE IF NOT EXISTS "api_keys" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "name" text NOT NULL,
  "key_prefix" text NOT NULL,
  "last4" text NOT NULL,
  "key_hash" text NOT NULL,
  "scopes" text[] NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "last_used_at" timestamp with time zone,
  "last_ip" text,
  "revoked_at" timestamp with time zone
);

CREATE UNIQUE INDEX IF NOT EXISTS "api_keys_hash_uidx" ON "api_keys" ("key_hash");
CREATE INDEX IF NOT EXISTS "api_keys_user_id_idx" ON "api_keys" ("user_id");

CREATE TABLE IF NOT EXISTS "api_key_usage_daily" (
  "api_key_id" uuid NOT NULL REFERENCES "api_keys" ("id") ON DELETE CASCADE,
  "day" date NOT NULL,
  "count" integer DEFAULT 0 NOT NULL,
  PRIMARY KEY ("api_key_id", "day")
);

-- Reserved Custom Names
CREATE TABLE IF NOT EXISTS "reserved_names" (
  "name" text PRIMARY KEY NOT NULL,
  "reason" text DEFAULT 'reserved' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

INSERT INTO "reserved_names" ("name", "reason") VALUES
  ('admin', 'system_reserved'),
  ('administrator', 'system_reserved'),
  ('support', 'system_reserved'),
  ('abuse', 'system_reserved'),
  ('postmaster', 'rfc_reserved'),
  ('hostmaster', 'rfc_reserved'),
  ('webmaster', 'rfc_reserved'),
  ('mailer-daemon', 'rfc_reserved'),
  ('root', 'system_reserved'),
  ('security', 'system_reserved'),
  ('noreply', 'system_reserved'),
  ('no-reply', 'system_reserved'),
  ('info', 'system_reserved'),
  ('billing', 'system_reserved'),
  ('temporamail', 'brand_reserved'),
  ('help', 'system_reserved'),
  ('contact', 'system_reserved'),
  ('api', 'system_reserved'),
  ('mail', 'system_reserved'),
  ('www', 'system_reserved')
ON CONFLICT ("name") DO NOTHING;

-- Separate Admin Users & Recovery Codes
CREATE TABLE IF NOT EXISTS "admin_users" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "email" citext NOT NULL,
  "password_hash" text NOT NULL,
  "role" text DEFAULT 'viewer' NOT NULL,
  "totp_secret_encrypted" text,
  "totp_enabled" boolean DEFAULT false NOT NULL,
  "status" text DEFAULT 'active' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "last_login_at" timestamp with time zone
);

CREATE UNIQUE INDEX IF NOT EXISTS "admin_users_email_uidx" ON "admin_users" ("email");

CREATE TABLE IF NOT EXISTS "admin_recovery_codes" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "admin_user_id" uuid NOT NULL REFERENCES "admin_users" ("id") ON DELETE CASCADE,
  "code_hash" text NOT NULL,
  "used_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "admin_recovery_codes_admin_id_idx" ON "admin_recovery_codes" ("admin_user_id");

-- Site Announcements
CREATE TABLE IF NOT EXISTS "announcements" (
  "id" serial PRIMARY KEY NOT NULL,
  "title" text NOT NULL,
  "body" text NOT NULL,
  "severity" text DEFAULT 'info' NOT NULL,
  "active" boolean DEFAULT false NOT NULL,
  "starts_at" timestamp with time zone,
  "ends_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "announcements_active_idx" ON "announcements" ("active");
