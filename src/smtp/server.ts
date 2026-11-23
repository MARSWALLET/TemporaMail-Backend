import { readFileSync } from 'node:fs';
import {
  SMTPServer,
  type SMTPServerAddress,
  type SMTPServerDataStream,
  type SMTPServerOptions,
  type SMTPServerSession,
} from 'smtp-server';
import type { Redis } from 'ioredis';
import type { Logger } from 'pino';
import type { EnvConfig } from '../config/env.js';
import { accountInboxCacheExists, inboxExists, isIpBanned } from '../storage/redis.js';
import { extractDomain, normalizeAddress } from '../utils/address.js';

export interface IncomingSmtpMessage {
  readonly sessionId: string;
  readonly remoteAddress: string;
  readonly mailFrom: string;
  readonly rcptTo: readonly string[];
  readonly raw: Buffer;
  readonly receivedAt: Date;
}

export interface SmtpError extends Error {
  responseCode?: number;
}

export interface SmtpServerHooks {
  /** Optional DNSBL check hook (implemented in Step 5). Return rejection reason or null. */
  readonly checkDnsbl?: (ip: string) => Promise<string | null>;
  /** Optional per-IP message rate limit hook (implemented in Step 5). Return rejection reason or null. */
  readonly checkIpRateLimit?: (ip: string) => Promise<string | null>;
  /** Dynamic allowed domains provider (backed by Postgres live settings in Step 6). */
  readonly getAllowedDomains?: () => readonly string[];
  /** Optional fallback check for active account-owned inboxes stored in Postgres (Part B6). */
  readonly hasAccountInbox?: (address: string) => Promise<boolean>;
  /** Handler called when a valid message is fully received. */
  readonly onMessage: (message: IncomingSmtpMessage) => Promise<void>;
}

export interface SmtpServerDependencies {
  readonly config: EnvConfig;
  readonly redis: Redis;
  readonly logger: Logger;
  readonly hooks: SmtpServerHooks;
}

const BASIC_EMAIL_REGEX = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;

function createSmtpError(message: string, responseCode: number): SmtpError {
  const err: SmtpError = new Error(message);
  err.responseCode = responseCode;
  return err;
}

function isValidSenderAddress(address: string): boolean {
  // RFC 5321 allows null reverse-path <> for bounce/DSN messages
  if (address === '') {
    return true;
  }
  if (address.length > 254) {
    return false;
  }
  return BASIC_EMAIL_REGEX.test(address);
}

function readStreamWithLimit(stream: SMTPServerDataStream, maxBytes: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let exceeded = false;

    stream.on('data', (chunk: Buffer | string) => {
      if (exceeded) {
        return;
      }

      const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
      totalBytes += buf.length;

      if (totalBytes > maxBytes) {
        exceeded = true;
        chunks.length = 0;
        return;
      }

      chunks.push(buf);
    });

    stream.on('error', (err: Error) => {
      reject(err);
    });

    stream.on('end', () => {
      if (exceeded || stream.sizeExceeded) {
        reject(createSmtpError('5.3.4 Message size exceeds fixed maximum message size', 552));
        return;
      }
      resolve(Buffer.concat(chunks, totalBytes));
    });
  });
}

export function createSmtpServer(deps: SmtpServerDependencies): SMTPServer {
  const { config, redis, logger, hooks } = deps;
  const activeConnectionsByIp = new Map<string, number>();

  const disabledCommands: string[] = ['AUTH'];
  let tlsOptions: { key: Buffer; cert: Buffer } | undefined;

  if (config.tlsKeyPath && config.tlsCertPath) {
    tlsOptions = {
      key: readFileSync(config.tlsKeyPath),
      cert: readFileSync(config.tlsCertPath),
    };
  } else {
    // Disable STARTTLS advertisement when no TLS certificate is configured (e.g. local dev/test)
    disabledCommands.push('STARTTLS');
  }

  const serverOptions: SMTPServerOptions = {
    name: config.mailHostname,
    banner: `${config.mailHostname} ESMTP TemporaMail`,
    authOptional: true,
    disabledCommands,
    size: config.maxMessageBytes,
    maxClients: config.smtpMaxClients,
    secure: false,
    ...(tlsOptions ? { key: tlsOptions.key, cert: tlsOptions.cert } : {}),

    onConnect(session: SMTPServerSession, callback: (err?: Error | null) => void): void {
      const ip = session.remoteAddress;

      void (async () => {
        try {
          if (await isIpBanned(redis, ip)) {
            logger.warn({ ip, sessionId: session.id, reason: 'ip_banned' }, 'SMTP connection rejected');
            callback(createSmtpError('5.7.1 Connection rejected', 554));
            return;
          }

          const currentConnections = activeConnectionsByIp.get(ip) ?? 0;
          if (currentConnections >= config.smtpMaxConnectionsPerIp) {
            logger.warn(
              { ip, sessionId: session.id, currentConnections, reason: 'max_connections_per_ip' },
              'SMTP connection rejected',
            );
            callback(createSmtpError('4.7.0 Too many concurrent connections from your IP', 421));
            return;
          }

          if (hooks.checkIpRateLimit) {
            const rateLimitReason = await hooks.checkIpRateLimit(ip);
            if (rateLimitReason) {
              logger.warn(
                { ip, sessionId: session.id, reason: rateLimitReason },
                'SMTP connection rejected by rate limit',
              );
              callback(createSmtpError('4.7.0 Rate limit exceeded, try again later', 421));
              return;
            }
          }

          if (hooks.checkDnsbl) {
            const dnsblReason = await hooks.checkDnsbl(ip);
            if (dnsblReason) {
              logger.warn(
                { ip, sessionId: session.id, reason: dnsblReason },
                'SMTP connection rejected by DNSBL',
              );
              callback(createSmtpError('5.7.1 Service unavailable; client host blocked', 554));
              return;
            }
          }

          activeConnectionsByIp.set(ip, currentConnections + 1);
          callback();
        } catch (err) {
          logger.error({ err, ip, sessionId: session.id }, 'Error during SMTP onConnect');
          callback(createSmtpError('4.3.0 Temporary server error', 451));
        }
      })();
    },

    onClose(session: SMTPServerSession): void {
      const ip = session.remoteAddress;
      const current = activeConnectionsByIp.get(ip) ?? 0;
      if (current <= 1) {
        activeConnectionsByIp.delete(ip);
      } else {
        activeConnectionsByIp.set(ip, current - 1);
      }
    },

    onMailFrom(
      address: SMTPServerAddress,
      session: SMTPServerSession,
      callback: (err?: Error | null) => void,
    ): void {
      const sender = address.address.trim();
      if (!isValidSenderAddress(sender)) {
        logger.warn(
          { ip: session.remoteAddress, sessionId: session.id, sender, reason: 'invalid_mail_from' },
          'SMTP MAIL FROM rejected',
        );
        callback(createSmtpError('5.1.7 Invalid sender address syntax', 501));
        return;
      }

      callback();
    },

    onRcptTo(
      address: SMTPServerAddress,
      session: SMTPServerSession,
      callback: (err?: Error | null) => void,
    ): void {
      const recipient = normalizeAddress(address.address);
      const ip = session.remoteAddress;

      void (async () => {
        try {
          if (session.envelope.rcptTo.length >= config.smtpMaxRecipients) {
            logger.warn(
              { ip, sessionId: session.id, recipient, reason: 'too_many_recipients' },
              'SMTP RCPT TO rejected',
            );
            callback(createSmtpError('4.5.3 Too many recipients', 452));
            return;
          }

          const domain = extractDomain(recipient);
          const allowedDomains = hooks.getAllowedDomains
            ? hooks.getAllowedDomains()
            : config.allowedDomains;

          if (!domain || !allowedDomains.includes(domain)) {
            logger.warn(
              { ip, sessionId: session.id, recipient, domain, reason: 'domain_not_allowed' },
              'SMTP RCPT TO rejected (relay/unknown domain)',
            );
            callback(createSmtpError('5.1.1 Mailbox does not exist', 550));
            return;
          }

          const existsInRedis =
            (await inboxExists(redis, recipient)) ||
            (await accountInboxCacheExists(redis, recipient));
          const existsInAccountDb =
            !existsInRedis && hooks.hasAccountInbox
              ? await hooks.hasAccountInbox(recipient)
              : false;

          if (!existsInRedis && !existsInAccountDb) {
            logger.info(
              { ip, sessionId: session.id, recipient, reason: 'mailbox_not_found' },
              'SMTP RCPT TO rejected',
            );
            callback(createSmtpError('5.1.1 Mailbox does not exist', 550));
            return;
          }

          callback();
        } catch (err) {
          logger.error({ err, ip, sessionId: session.id, recipient }, 'Error during SMTP onRcptTo');
          callback(createSmtpError('4.3.0 Temporary server error', 451));
        }
      })();
    },

    onData(
      stream: SMTPServerDataStream,
      session: SMTPServerSession,
      callback: (err?: Error | null) => void,
    ): void {
      const ip = session.remoteAddress;
      const mailFrom =
        session.envelope.mailFrom === false ? '' : normalizeAddress(session.envelope.mailFrom.address);
      const rcptTo = session.envelope.rcptTo.map((r) => normalizeAddress(r.address));

      void (async () => {
        try {
          const raw = await readStreamWithLimit(stream, config.maxMessageBytes);

          await hooks.onMessage({
            sessionId: session.id,
            remoteAddress: ip,
            mailFrom,
            rcptTo,
            raw,
            receivedAt: new Date(),
          });

          callback();
        } catch (err) {
          const smtpErr = err as SmtpError;
          if (smtpErr.responseCode) {
            logger.warn(
              {
                ip,
                sessionId: session.id,
                mailFrom,
                rcptTo,
                responseCode: smtpErr.responseCode,
                reason: smtpErr.message,
              },
              'SMTP DATA rejected',
            );
            callback(smtpErr);
            return;
          }

          logger.error({ err, ip, sessionId: session.id, mailFrom, rcptTo }, 'Error processing SMTP DATA');
          callback(createSmtpError('4.3.0 Temporary message processing failure', 451));
        }
      })();
    },
  };

  const server = new SMTPServer(serverOptions);

  server.on('error', (err: Error) => {
    logger.error({ err }, 'SMTP server error');
  });

  return server;
}
