import type { FastifyInstance } from 'fastify';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { z } from 'zod';
import { ApiError } from '../api/errors.js';
import type { EnvConfig } from '../config/env.js';
import { getInbox, getInboxMessage } from '../storage/redis.js';
import { normalizeAddress } from '../utils/address.js';
import type { InboxEventHub } from './pubsub.js';

export interface SseRouteDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  readonly eventHub: InboxEventHub;
  readonly heartbeatMs?: number;
}

const addressParamSchema = z.object({
  address: z
    .string()
    .trim()
    .min(3)
    .max(254)
    .refine((val) => val.includes('@'), { message: 'Invalid email address format' }),
});

const DEFAULT_HEARTBEAT_MS = 25_000;
const MAX_TIMEOUT_MS = 2_147_483_647;

export async function registerSseRoute(
  app: FastifyInstance,
  deps: SseRouteDependencies,
): Promise<void> {
  const { config, redis, logger, eventHub, heartbeatMs = DEFAULT_HEARTBEAT_MS } = deps;

  app.get('/inbox/:address/stream', async (request, reply) => {
    const { address: rawAddress } = addressParamSchema.parse(request.params);
    const address = normalizeAddress(rawAddress);
    const inbox = await getInbox(redis, address);

    if (!inbox) {
      throw new ApiError(404, 'INBOX_NOT_FOUND', 'Inbox does not exist or has expired');
    }

    const headers: Record<string, string> = {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    };

    const origin = request.headers.origin;
    if (typeof origin === 'string' && config.corsOrigins.includes(origin)) {
      headers['Access-Control-Allow-Origin'] = origin;
      headers['Access-Control-Allow-Credentials'] = 'true';
      headers['Vary'] = 'Origin';
    }

    reply.hijack();
    reply.raw.writeHead(200, headers);
    reply.raw.write(': connected\n\n');

    let closed = false;
    let expiryTimer: ReturnType<typeof setTimeout> | undefined;

    const writeChunk = (chunk: string): void => {
      if (closed || reply.raw.writableEnded || reply.raw.destroyed) {
        return;
      }
      reply.raw.write(chunk);
    };

    const cleanup = (): void => {
      if (closed) {
        return;
      }
      closed = true;
      clearInterval(heartbeatTimer);
      if (expiryTimer !== undefined) {
        clearTimeout(expiryTimer);
        expiryTimer = undefined;
      }
      unsubscribe();
      if (!reply.raw.writableEnded && !reply.raw.destroyed) {
        reply.raw.end();
      }
    };

    const unsubscribe = eventHub.subscribe(address, (msgId) => {
      void (async () => {
        try {
          const message = await getInboxMessage(redis, address, msgId);
          if (!message || closed) {
            return;
          }
          const summary = {
            id: message.id,
            from: message.from,
            subject: message.subject,
            date: message.date,
            hasOtp: message.otp !== null,
            spamFlagged: message.spamFlagged,
            attachmentCount: message.attachments.length,
          };
          writeChunk(`event: message\ndata: ${JSON.stringify(summary)}\n\n`);
        } catch (err) {
          logger.error({ err, address, msgId }, 'Failed to fetch message for SSE event');
        }
      })();
    });

    const heartbeatTimer = setInterval(() => {
      writeChunk(': heartbeat\n\n');
    }, heartbeatMs);

    const scheduleExpiryCheck = (expiresAt: number): void => {
      if (closed) {
        return;
      }
      const delay = Math.min(Math.max(100, expiresAt - Date.now()), MAX_TIMEOUT_MS);
      expiryTimer = setTimeout(() => {
        void (async () => {
          try {
            const current = await getInbox(redis, address);
            if (!current || current.expiresAt <= Date.now()) {
              writeChunk(`event: expired\ndata: ${JSON.stringify({ address })}\n\n`);
              cleanup();
              return;
            }
            // Inbox was extended while stream was open; reschedule
            scheduleExpiryCheck(current.expiresAt);
          } catch (err) {
            logger.error({ err, address }, 'Error checking inbox expiry for SSE stream');
            cleanup();
          }
        })();
      }, delay);
    };

    scheduleExpiryCheck(inbox.expiresAt);

    request.raw.on('close', cleanup);
    request.raw.on('error', cleanup);
  });
}
