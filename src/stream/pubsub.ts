import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import { normalizeAddress } from '../utils/address.js';

export type InboxMessageListener = (msgId: string) => void;

const CHANNEL_PREFIX = 'new:';
const CHANNEL_PATTERN = 'new:*';

export class InboxEventHub {
  private readonly subscriber: Redis;
  private readonly logger: Logger;
  private readonly listeners = new Map<string, Set<InboxMessageListener>>();
  private started = false;
  private closed = false;

  constructor(subscriber: Redis, logger: Logger) {
    this.subscriber = subscriber;
    this.logger = logger;
  }

  async start(): Promise<void> {
    if (this.started || this.closed) {
      return;
    }
    this.started = true;

    this.subscriber.on('pmessage', (_pattern: string, channel: string, message: string) => {
      if (!channel.startsWith(CHANNEL_PREFIX)) {
        return;
      }
      const address = normalizeAddress(channel.slice(CHANNEL_PREFIX.length));
      const addressListeners = this.listeners.get(address);
      if (!addressListeners || addressListeners.size === 0) {
        return;
      }

      for (const listener of addressListeners) {
        try {
          listener(message);
        } catch (err) {
          this.logger.error({ err, address, msgId: message }, 'SSE listener callback failed');
        }
      }
    });

    await this.subscriber.psubscribe(CHANNEL_PATTERN);
  }

  subscribe(address: string, listener: InboxMessageListener): () => void {
    const normalized = normalizeAddress(address);
    let set = this.listeners.get(normalized);
    if (!set) {
      set = new Set<InboxMessageListener>();
      this.listeners.set(normalized, set);
    }
    set.add(listener);

    return () => {
      const current = this.listeners.get(normalized);
      if (!current) {
        return;
      }
      current.delete(listener);
      if (current.size === 0) {
        this.listeners.delete(normalized);
      }
    };
  }

  getListenerCount(address?: string): number {
    if (address !== undefined) {
      return this.listeners.get(normalizeAddress(address))?.size ?? 0;
    }
    let total = 0;
    for (const set of this.listeners.values()) {
      total += set.size;
    }
    return total;
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.listeners.clear();

    if (this.started) {
      try {
        await this.subscriber.punsubscribe(CHANNEL_PATTERN);
      } catch {
        // Ignore unsubscribe errors during shutdown
      }
    }

    try {
      await this.subscriber.quit();
    } catch {
      this.subscriber.disconnect();
    }
  }
}
