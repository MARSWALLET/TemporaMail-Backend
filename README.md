# TemporaMail Backend

Receive-only temporary email backend for `temporamail.app`.

## Implemented So Far
- **Step 0**: Strict TypeScript project scaffolding, Zod env config, Pino logger, cryptographic address/token generator, Redis storage & `setInboxTTL` helper.
- **Step 1**: Inbound SMTP receiver (`smtp-server`) with `STARTTLS` support, disabled `AUTH`, per-IP connection limits, IP ban check, recipient lookup against Redis, max recipient cap, and hard message size cap.
- **Step 2**: Message pipeline & storage (`mailparser`, `sanitize-html` with remote content detection, OTP & verification link extraction, dangerous attachment blocking & size limits, Redis message/attachment storage, `MAX_MESSAGES_PER_INBOX` trimming with eviction cleanup, and `new:{address}` pub/sub publishing).
- **Step 3**: Fastify REST API (`/api/v1`) with Zod validation, `@fastify/cors`, `@fastify/helmet`, `@fastify/rate-limit`, `ownerToken` enforcement, safe attachment downloads, and consistent `{ error: { code, message } }` responses.
- **Step 4**: Live Stream (SSE) on `GET /api/v1/inbox/:address/stream` backed by a single shared Redis `psubscribe('new:*')` fan-out hub, 25s heartbeats, expiry auto-close, and automatic disconnect cleanup.
- **Step 5**: Protection layer (SMTP IP rate limits + 1-hour repeat-offender auto-ban, DNSBL with 10-min Redis cache & fail-open, `mailauth` SPF/DKIM/DMARC with hard DMARC reject, Rspamd `/checkv2` scoring with fail-open, in-memory blocklists, inbox-creation abuse detection, and Cloudflare Turnstile verification).
- **Step 6**: PostgreSQL (`drizzle-orm` + `pg`) schema & SQL migration (`domains`, `blocklist`, `settings`, `abuse_reports`, `smtp_log`, `audit_log`), typed repositories, and `LiveSettingsStore` with 60-second in-memory refresh for domains, blocklists, and tunable settings.

## Local Development

1. Start Redis:
   ```bash
   docker compose -f docker-compose.dev.yml up -d
   ```

2. Copy environment config:
   ```bash
   cp .env.example .env
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

4. Run the SMTP server (defaults to port `2525` in development):
   ```bash
   npm run dev:smtp
   ```

5. Run tests and typecheck:
   ```bash
   npm run typecheck
   npm test
   ```
