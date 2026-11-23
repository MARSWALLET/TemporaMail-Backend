# TemporaMail Backend

Receive-only temporary email backend for `temporamail.app`.

## Implemented So Far
- **Step 0**: Strict TypeScript project scaffolding, Zod env config, Pino logger, cryptographic address/token generator, Redis storage & `setInboxTTL` helper.
- **Step 1**: Inbound SMTP receiver (`smtp-server`) with `STARTTLS` support, disabled `AUTH`, per-IP connection limits, IP ban check, recipient lookup against Redis, max recipient cap, and hard message size cap.

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
