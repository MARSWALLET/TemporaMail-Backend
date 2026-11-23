import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import type { Redis } from 'ioredis';
import type { SMTPServer } from 'smtp-server';
import { loadEnv } from '../src/config/env.js';
import { createSmtpServer, type IncomingSmtpMessage } from '../src/smtp/server.js';
import { createInbox, redisKeys } from '../src/storage/redis.js';
import { createLogger } from '../src/utils/logger.js';

function createMockRedis(): Redis {
  const mock = new RedisMock();
  return mock as unknown as Redis;
}

class SimpleSmtpClient {
  private readonly socket: net.Socket;
  private buffer = '';
  private readonly linesQueue: string[] = [];
  private readonly waiters: Array<(line: string) => void> = [];

  private constructor(socket: net.Socket) {
    this.socket = socket;
    this.socket.setEncoding('utf8');
    this.socket.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.flushLines();
    });
  }

  static connect(port: number): Promise<SimpleSmtpClient> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
        resolve(new SimpleSmtpClient(socket));
      });
      socket.once('error', reject);
    });
  }

  private flushLines(): void {
    while (this.buffer.includes('\r\n')) {
      const idx = this.buffer.indexOf('\r\n');
      const line = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 2);
      const waiter = this.waiters.shift();
      if (waiter) {
        waiter(line);
      } else {
        this.linesQueue.push(line);
      }
    }
  }

  private readLine(): Promise<string> {
    const queued = this.linesQueue.shift();
    if (queued !== undefined) {
      return Promise.resolve(queued);
    }
    return new Promise((resolve) => {
      this.waiters.push(resolve);
    });
  }

  async readResponse(): Promise<string> {
    const lines: string[] = [];
    for (;;) {
      const line = await this.readLine();
      lines.push(line);
      if (/^\d{3} /.test(line)) {
        return lines.join('\n');
      }
    }
  }

  async command(cmd: string): Promise<string> {
    this.socket.write(`${cmd}\r\n`);
    return this.readResponse();
  }

  async sendData(rawMessage: string): Promise<string> {
    this.socket.write(`${rawMessage}\r\n.\r\n`);
    return this.readResponse();
  }

  close(): void {
    this.socket.destroy();
  }
}

async function startServer(
  redis: Redis,
  received: IncomingSmtpMessage[],
  overrides: NodeJS.ProcessEnv = {},
): Promise<{ server: SMTPServer; port: number }> {
  const config = loadEnv({
    NODE_ENV: 'test',
    PRIMARY_DOMAIN: 'temporamail.app',
    MAIL_HOSTNAME: 'mail.temporamail.app',
    ALLOWED_DOMAINS: 'temporamail.app,alt.temporamail.app',
    MAX_MESSAGE_BYTES: '4096',
    SMTP_MAX_CONNECTIONS_PER_IP: '2',
    SMTP_MAX_RECIPIENTS: '5',
    ...overrides,
  });

  const logger = createLogger('smtp-test', 'silent', 'test');
  const server = createSmtpServer({
    config,
    redis,
    logger,
    hooks: {
      async onMessage(message) {
        received.push(message);
      },
    },
  });

  const port = await new Promise<number>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.server.address() as AddressInfo | null;
      if (!addr) {
        reject(new Error('SMTP server did not bind to a port'));
        return;
      }
      resolve(addr.port);
    });
  });

  return { server, port };
}

describe('Step 1: SMTP receiver', () => {
  const openServers: SMTPServer[] = [];

  afterEach(async () => {
    const cleanupRedis = createMockRedis();
    await cleanupRedis.flushall();
    while (openServers.length > 0) {
      const server = openServers.pop();
      if (server) {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    }
  });

  it('accepts email for an existing inbox and passes raw payload to onMessage', async () => {
    const redis = createMockRedis();
    const received: IncomingSmtpMessage[] = [];
    const { server, port } = await startServer(redis, received);
    openServers.push(server);

    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });

    const client = await SimpleSmtpClient.connect(port);
    try {
      const greeting = await client.readResponse();
      expect(greeting).toContain('220');
      expect(greeting).toContain('mail.temporamail.app');

      const ehlo = await client.command('EHLO sender.example.com');
      expect(ehlo).toContain('250');
      expect(ehlo).not.toContain('AUTH');

      const authRes = await client.command('AUTH PLAIN dGVzdA==');
      expect(authRes.startsWith('500') || authRes.startsWith('502') || authRes.startsWith('503')).toBe(
        true,
      );

      expect((await client.command('MAIL FROM:<alice@example.com>')).startsWith('250')).toBe(true);
      expect((await client.command(`RCPT TO:<${inbox.address}>`)).startsWith('250')).toBe(true);
      expect((await client.command('DATA')).startsWith('354')).toBe(true);

      const rawBody = [
        'From: Alice <alice@example.com>',
        `To: ${inbox.address}`,
        'Subject: Hello TemporaMail',
        '',
        'Your verification code is 482910.',
      ].join('\r\n');

      const dataRes = await client.sendData(rawBody);
      expect(dataRes.startsWith('250')).toBe(true);
      await client.command('QUIT');
    } finally {
      client.close();
    }

    expect(received).toHaveLength(1);
    expect(received[0]?.mailFrom).toBe('alice@example.com');
    expect(received[0]?.rcptTo).toEqual([inbox.address]);
    expect(received[0]?.raw.toString('utf8')).toContain('482910');
  });

  it('rejects unknown, expired, and wrong-domain recipients with 550', async () => {
    const redis = createMockRedis();
    const received: IncomingSmtpMessage[] = [];
    const { server, port } = await startServer(redis, received);
    openServers.push(server);

    const expiredInbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });
    // Simulate expiration by deleting the inbox key
    await redis.del(redisKeys.inbox(expiredInbox.address));

    const client = await SimpleSmtpClient.connect(port);
    try {
      await client.readResponse();
      await client.command('EHLO sender.example.com');
      await client.command('MAIL FROM:<alice@example.com>');

      const unknownRes = await client.command('RCPT TO:<nonexistent@temporamail.app>');
      expect(unknownRes).toContain('550');
      expect(unknownRes).toContain('Mailbox does not exist');

      const expiredRes = await client.command(`RCPT TO:<${expiredInbox.address}>`);
      expect(expiredRes).toContain('550');

      const relayRes = await client.command('RCPT TO:<victim@gmail.com>');
      expect(relayRes).toContain('550');

      await client.command('QUIT');
    } finally {
      client.close();
    }

    expect(received).toHaveLength(0);
  });

  it('enforces maximum of 5 recipients per message', async () => {
    const redis = createMockRedis();
    const received: IncomingSmtpMessage[] = [];
    const { server, port } = await startServer(redis, received);
    openServers.push(server);

    const addresses: string[] = [];
    for (let i = 0; i < 6; i += 1) {
      const inbox = await createInbox(redis, {
        domain: 'temporamail.app',
        ttlSeconds: 600,
        ip: '127.0.0.1',
      });
      addresses.push(inbox.address);
    }

    const client = await SimpleSmtpClient.connect(port);
    try {
      await client.readResponse();
      await client.command('EHLO sender.example.com');
      await client.command('MAIL FROM:<alice@example.com>');

      for (let i = 0; i < 5; i += 1) {
        const res = await client.command(`RCPT TO:<${addresses[i]}>`);
        expect(res.startsWith('250')).toBe(true);
      }

      const sixthRes = await client.command(`RCPT TO:<${addresses[5]}>`);
      expect(sixthRes).toContain('452');
      await client.command('QUIT');
    } finally {
      client.close();
    }
  });

  it('rejects connections from banned IPs with 554', async () => {
    const redis = createMockRedis();
    await redis.set(redisKeys.banIp('127.0.0.1'), '1', 'EX', 3600);

    const received: IncomingSmtpMessage[] = [];
    const { server, port } = await startServer(redis, received);
    openServers.push(server);

    const client = await SimpleSmtpClient.connect(port);
    try {
      const greeting = await client.readResponse();
      expect(greeting).toContain('554');
    } finally {
      client.close();
    }
  });

  it('rejects messages exceeding MAX_MESSAGE_BYTES with 552', async () => {
    const redis = createMockRedis();
    const received: IncomingSmtpMessage[] = [];
    const { server, port } = await startServer(redis, received, {
      MAX_MESSAGE_BYTES: '1024',
    });
    openServers.push(server);

    const inbox = await createInbox(redis, {
      domain: 'temporamail.app',
      ttlSeconds: 600,
      ip: '127.0.0.1',
    });

    const client = await SimpleSmtpClient.connect(port);
    try {
      await client.readResponse();
      await client.command('EHLO sender.example.com');
      await client.command('MAIL FROM:<alice@example.com>');
      await client.command(`RCPT TO:<${inbox.address}>`);
      await client.command('DATA');

      const oversizedBody = `Subject: Big\r\n\r\n${'A'.repeat(2048)}`;
      const res = await client.sendData(oversizedBody);
      expect(res).toContain('552');
    } finally {
      client.close();
    }

    expect(received).toHaveLength(0);
  });
});
