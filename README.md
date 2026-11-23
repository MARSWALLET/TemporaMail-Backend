# TemporaMail Backend (`temporamail.app`)

Receive-only temporary email backend with optional user accounts, API keys, and a role-based admin system — built with strict TypeScript, Node.js 20+, Fastify, `smtp-server`, Redis, PostgreSQL (`drizzle-orm`), Rspamd, and Caddy.

## Implemented Capabilities

### Phase A — Core Temporary Email Backend (Steps 0–8)
- **Inbound SMTP Receiver**: `smtp-server` on port `25` (`2525` in dev), `AUTH` disabled, `STARTTLS`, per-IP connection limits, IP ban check, Redis + account inbox `RCPT TO` validation, max 5 recipients, hard `MAX_MESSAGE_BYTES` cap.
- **Message Pipeline**: `mailparser`, `sanitize-html` (strips scripts, iframes, forms, event handlers, remote resources + `hasRemoteContent` flag), OTP & verification link extraction, dangerous attachment extension blocking, Redis message/attachment storage with unified `setInboxTTL`, `MAX_MESSAGES_PER_INBOX` eviction cleanup, `new:{address}` pub/sub.
- **REST API (`/api/v1`) & Live Stream (SSE)**: Fastify + Zod + Helmet + strict CORS + Redis rate limits, `ownerToken` enforcement, safe attachment downloads (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`), single shared Redis `psubscribe('new:*')` SSE fan-out with 25s heartbeats and expiry auto-close.
- **Protection Layer**: SMTP IP rate limits + 1h repeat-offender auto-ban, DNSBL with 10-min Redis cache & fail-open, `mailauth` SPF/DKIM/DMARC (hard DMARC reject), Rspamd `/checkv2` fail-open scoring, in-memory blocklists, Cloudflare Turnstile, zero greylisting.
- **PostgreSQL & Live Settings**: Drizzle ORM + SQL migrations (`drizzle/0000_core_tables.sql`, `drizzle/0001_accounts_apikeys_admin.sql`), 60-second `LiveSettingsStore`, maintenance jobs (5-min Redis/account cleanup, 7-day `smtp_log` purge, daily MX/DNS/TLS health check).

### Phase B — Accounts, API Keys & Real Admin System (Parts B1–B9)
- **Outbound Transactional SMTP Mailer**: Separate Nodemailer SMTP config (`SMTP_OUTBOUND_*`) with HTML-escaped templates for verification, password reset, login alerts, 2FA, and API key creation.
- **Auth & Sessions (`/api/v1/auth/*`, `/api/v1/account/*`)**: `argon2id` hashing (min 10 chars, common password blocklist, constant-time dummy hash check), disposable + own-domain signup blocking, Redis server-side sessions (`__Host-tm_session`), CSRF header checks, 5-attempt lockout, GDPR data export (`/account/export`), and account deletion.
- **Google OAuth**: Authorization Code + `S256` PKCE, `jose` JWKS ID token verification (`aud`, `iss`, `exp`, `nonce`, `email_verified: true`), verified-only account linking.
- **User 2FA**: `otplib` TOTP, AES-256-GCM encrypted secrets at rest, 10 single-use SHA-256 hashed recovery codes, TOTP replay lock, rate-limited `/auth/login/mfa`.
- **Plans & Account-Owned Inboxes**: Centralized `getEntitlements(user)` backed by `plans`, Postgres-stored `user_inboxes` & `account_messages`, custom names (3–30 chars + `reserved_names`), dual-store SMTP & SSE routing.
- **API Keys**: `tm_live_` + 32-byte Base62 shown once, SHA-256 hash-only storage, scopes (`inbox:create`, `inbox:read`, `inbox:delete`, `messages:read`), immediate revocation, per-key daily Redis rate limit (`429 Retry-After`), CAPTCHA skip on `POST /inbox`, daily usage tracking.
- **Real Admin System (`/admin/api/v1/*`)**: Separate `admin_users` table, separate cookie (`__Host-tm_admin_session`) & Redis namespace (`sess:admin:*`, 8h max / 30m idle), mandatory TOTP 2FA, RBAC (`owner`, `admin`, `moderator`, `viewer`), audit-logged inbox lookup with mandatory `reason`, user ban (destroys sessions + revokes API keys), and break-glass CLI.
- **Hardening**: Pino log redaction for passwords, tokens, API keys, cookies, and TOTP secrets; strict production CORS defaults (`https://temporamail.app`, `https://admin.temporamail.app`).

## Local Development

```bash
# 1. Start Redis & PostgreSQL
docker compose -f docker-compose.dev.yml up -d

# 2. Configure environment
cp .env.example .env

# 3. Install dependencies & push schema
npm install
npm run db:push

# 4. Run API & SMTP in separate terminals
npm run dev:api
npm run dev:smtp

# 5. Break-glass Admin CLI (create owner or reset 2FA)
npm run admin:cli -- create-owner owner@temporamail.app "strong owner passphrase"
npm run admin:cli -- reset-2fa owner@temporamail.app

# 6. Typecheck, build & test
npm run typecheck
npm run build
npm test
```

## Production (`docker compose up`)

1. Place Let's Encrypt certs (`privkey.pem`, `fullchain.pem`) in `./certs/`.
2. Set production secrets in `.env` (`REDIS_PASSWORD`, `POSTGRES_PASSWORD`, `TOTP_ENCRYPTION_KEY`, `TURNSTILE_SECRET`, `SMTP_OUTBOUND_*`, `GOOGLE_CLIENT_*`).
3. Start the full stack (`api`, `smtp`, `redis`, `postgres`, `rspamd`, `caddy`):
   ```bash
   docker compose up -d --build
   ```
