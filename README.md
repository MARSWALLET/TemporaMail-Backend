# TemporaMail Backend (`temporamail.app`)

Receive-only temporary email backend built with strict TypeScript, Node.js 20+, Fastify, `smtp-server`, Redis, PostgreSQL (`drizzle-orm`), Rspamd, and Caddy.

## Phase A: Core Backend (Steps 0–8 Complete)
- **Step 0**: Strict TypeScript scaffolding, Zod env config, Pino logger, crypto address/token generator, Redis storage & unified `setInboxTTL`.
- **Step 1**: Inbound SMTP receiver (`smtp-server`) with `STARTTLS`, disabled `AUTH`, per-IP connection limits, IP ban check, Redis recipient lookup, max-5-recipients cap, and hard message size cap.
- **Step 2**: Message pipeline (`mailparser`, `sanitize-html` with remote content flag, OTP & verification link extraction, dangerous attachment blocking, Redis storage, `MAX_MESSAGES_PER_INBOX` eviction cleanup, `new:{address}` pub/sub).
- **Step 3**: Fastify REST API (`/api/v1`) with Zod validation, CORS, Helmet, Redis-backed rate limits, `ownerToken` enforcement, safe attachment downloads, and consistent `{ error: { code, message } }` responses.
- **Step 4**: Live Stream (SSE) on `GET /api/v1/inbox/:address/stream` backed by a single shared Redis `psubscribe('new:*')` fan-out hub, 25s heartbeats, expiry auto-close, and disconnect cleanup.
- **Step 5**: Protection layer (SMTP IP rate limits + 1-hour auto-ban, DNSBL with 10-min Redis cache & fail-open, `mailauth` SPF/DKIM/DMARC with hard DMARC reject, Rspamd `/checkv2` fail-open scoring, in-memory blocklists, abuse detection, Cloudflare Turnstile).
- **Step 6**: PostgreSQL (`drizzle-orm` + `pg`) schema & migrations (`domains`, `blocklist`, `settings`, `abuse_reports`, `smtp_log`, `audit_log`), typed repositories, and 60-second `LiveSettingsStore`.
- **Step 7**: Admin API (`/api/v1/admin/*`) protected by constant-time `ADMIN_API_KEY` check with stats, domains/blocklist CRUD, settings, abuse reports, SMTP log search, inbox takedown, and `audit_log` on every mutation.
- **Step 8**: Maintenance jobs (5-min Redis orphan/TTL cleanup, 7-day `smtp_log` purge, daily MX/DNS/TLS health check), multi-stage `Dockerfile`, `Caddyfile`, and full `docker-compose.yml`.

## Local Development

1. Start Redis & PostgreSQL:
   ```bash
   docker compose -f docker-compose.dev.yml up -d
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   ```

3. Install dependencies & push schema:
   ```bash
   npm install
   npm run db:push
   ```

4. Run the two separate backend processes (in two terminals):
   ```bash
   npm run dev:api
   npm run dev:smtp
   ```

5. Run typecheck, build, and tests:
   ```bash
   npm run typecheck
   npm run build
   npm test
   ```

## Quick Test with `curl`

```bash
# Create an inbox
curl -s -X POST http://localhost:3000/api/v1/inbox -H "Content-Type: application/json" -d '{}'

# Stream new mail (SSE)
curl -N http://localhost:3000/api/v1/inbox/<address>/stream

# Health check
curl -s http://localhost:3000/api/v1/health
```

## Production (`docker compose up`)

1. Place Let's Encrypt certs (`privkey.pem`, `fullchain.pem`) in `./certs/`.
2. Set production secrets (`REDIS_PASSWORD`, `POSTGRES_PASSWORD`, `TURNSTILE_SECRET`, `ADMIN_API_KEY`, `CORS_ORIGINS`) in `.env`.
3. Launch all services (`api`, `smtp`, `redis`, `postgres`, `rspamd`, `caddy`):
   ```bash
   docker compose up -d --build
   ```
