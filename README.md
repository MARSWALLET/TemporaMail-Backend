# TemporaMail Backend

Receive-only temporary email backend for `temporamail.app`.

## Implemented So Far
- **Step 0**: Strict TypeScript project scaffolding, Zod env config, Pino logger, cryptographic address/token generator, Redis storage & `setInboxTTL` helper.
- **Step 1**: Inbound SMTP receiver (`smtp-server`) with `STARTTLS` support, disabled `AUTH`, per-IP connection limits, IP ban check, recipient lookup against Redis, max recipient cap, and hard message size cap.
- **Step 2**: Message pipeline & storage (`mailparser`, `sanitize-html` with remote content detection, OTP & verification link extraction, dangerous attachment blocking & size limits, Redis message/attachment storage, `MAX_MESSAGES_PER_INBOX` trimming with eviction cleanup, and `new:{address}` pub/sub publishing).
- **Step 3**: Fastify REST API (`/api/v1`) with Zod validation, `@fastify/cors`, `@fastify/helmet`, `@fastify/rate-limit`, `ownerToken` enforcement, safe attachment downloads, and consistent `{ error: { code, message } }` responses.

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
