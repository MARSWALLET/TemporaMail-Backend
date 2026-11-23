import 'dotenv/config';
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  PRIMARY_DOMAIN: z.string().trim().min(1).default('temporamail.app'),
  MAIL_HOSTNAME: z.string().trim().min(1).default('mail.temporamail.app'),
  ALLOWED_DOMAINS: z
    .string()
    .default('temporamail.app')
    .transform((value) =>
      value
        .split(',')
        .map((domain) => domain.trim().toLowerCase())
        .filter((domain) => domain.length > 0),
    )
    .refine((domains) => domains.length > 0, {
      message: 'ALLOWED_DOMAINS must contain at least one domain',
    }),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  REDIS_URL: z.string().trim().min(1).default('redis://localhost:6379'),
  DATABASE_URL: z.string().trim().optional().default(''),
  RSPAMD_URL: z.string().trim().default('http://localhost:11334'),
  DNS_RESOLVER: z.string().trim().default('127.0.0.1'),
  DEFAULT_TTL_MINUTES: z.coerce.number().int().min(1).default(10),
  MAX_TTL_MINUTES: z.coerce.number().int().min(1).default(60),
  MAX_MESSAGE_BYTES: z.coerce.number().int().min(1024).default(10_485_760),
  MAX_MESSAGES_PER_INBOX: z.coerce.number().int().min(1).default(50),
  SMTP_MAX_CLIENTS: z.coerce.number().int().min(1).default(100),
  SMTP_MAX_CONNECTIONS_PER_IP: z.coerce.number().int().min(1).default(5),
  SMTP_MAX_RECIPIENTS: z.coerce.number().int().min(1).default(5),
  SMTP_MAX_MESSAGES_PER_MIN: z.coerce.number().int().min(1).default(10),
  RSPAMD_REJECT_SCORE: z.coerce.number().min(0).default(15),
  RSPAMD_FLAG_SCORE: z.coerce.number().min(0).default(6),
  DNSBL_ZONES: z
    .string()
    .optional()
    .default('zen.spamhaus.org,bl.spamcop.net')
    .transform((value) =>
      value
        .split(',')
        .map((zone) => zone.trim().toLowerCase())
        .filter((zone) => zone.length > 0),
    ),
  CORS_ORIGINS: z
    .string()
    .optional()
    .default('')
    .transform((value) =>
      value
        .split(',')
        .map((origin) => origin.trim())
        .filter((origin) => origin.length > 0),
    ),
  API_RATE_LIMIT_PER_MIN: z.coerce.number().int().min(1).default(120),
  INBOX_CREATE_LIMIT_PER_HOUR: z.coerce.number().int().min(1).default(10),
  TURNSTILE_SECRET: z.string().trim().optional().default(''),
  ADMIN_API_KEY: z.string().trim().optional().default(''),
  TLS_KEY_PATH: z.string().trim().optional().default(''),
  TLS_CERT_PATH: z.string().trim().optional().default(''),
  APP_BASE_URL: z.string().trim().optional().default(''),
  SMTP_OUTBOUND_HOST: z.string().trim().optional().default(''),
  SMTP_OUTBOUND_PORT: z.coerce.number().int().min(1).max(65535).default(587),
  SMTP_OUTBOUND_SECURE: z
    .union([z.boolean(), z.string()])
    .optional()
    .default(false)
    .transform((v) => v === true || v === 'true' || v === '1'),
  SMTP_OUTBOUND_USER: z.string().trim().optional().default(''),
  SMTP_OUTBOUND_PASS: z.string().optional().default(''),
  SMTP_OUTBOUND_FROM: z
    .string()
    .trim()
    .default('TemporaMail <noreply@account.temporamail.app>'),
  GOOGLE_CLIENT_ID: z.string().trim().optional().default(''),
  GOOGLE_CLIENT_SECRET: z.string().trim().optional().default(''),
  GOOGLE_REDIRECT_URI: z.string().trim().optional().default(''),
  TOTP_ENCRYPTION_KEY: z.string().trim().optional().default(''),
});

export interface EnvConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
  readonly primaryDomain: string;
  readonly mailHostname: string;
  readonly allowedDomains: readonly string[];
  readonly smtpPort: number;
  readonly apiPort: number;
  readonly redisUrl: string;
  readonly databaseUrl: string;
  readonly rspamdUrl: string;
  readonly dnsResolver: string;
  readonly defaultTtlMinutes: number;
  readonly maxTtlMinutes: number;
  readonly maxMessageBytes: number;
  readonly maxMessagesPerInbox: number;
  readonly smtpMaxClients: number;
  readonly smtpMaxConnectionsPerIp: number;
  readonly smtpMaxRecipients: number;
  readonly smtpMaxMessagesPerMin: number;
  readonly rspamdRejectScore: number;
  readonly rspamdFlagScore: number;
  readonly dnsblZones: readonly string[];
  readonly corsOrigins: readonly string[];
  readonly apiRateLimitPerMin: number;
  readonly inboxCreateLimitPerHour: number;
  readonly turnstileSecret: string;
  readonly adminApiKey: string;
  readonly tlsKeyPath: string;
  readonly tlsCertPath: string;
  readonly appBaseUrl: string;
  readonly smtpOutboundHost: string;
  readonly smtpOutboundPort: number;
  readonly smtpOutboundSecure: boolean;
  readonly smtpOutboundUser: string;
  readonly smtpOutboundPass: string;
  readonly smtpOutboundFrom: string;
  readonly googleClientId: string;
  readonly googleClientSecret: string;
  readonly googleRedirectUri: string;
  readonly totpEncryptionKey: string;
}

export function loadEnv(source: NodeJS.ProcessEnv = process.env): EnvConfig {
  const parsed = envSchema.parse(source);
  const smtpPort = parsed.SMTP_PORT ?? (parsed.NODE_ENV === 'production' ? 25 : 2525);
  const appBaseUrl =
    parsed.APP_BASE_URL ||
    (parsed.NODE_ENV === 'production'
      ? `https://${parsed.PRIMARY_DOMAIN.toLowerCase()}`
      : 'http://localhost:3001');
  const corsOrigins =
    parsed.CORS_ORIGINS.length > 0
      ? parsed.CORS_ORIGINS
      : parsed.NODE_ENV === 'production'
        ? [`https://${parsed.PRIMARY_DOMAIN.toLowerCase()}`]
        : ['http://localhost:3000', 'http://localhost:3001'];

  if (parsed.DEFAULT_TTL_MINUTES > parsed.MAX_TTL_MINUTES) {
    throw new Error('DEFAULT_TTL_MINUTES cannot exceed MAX_TTL_MINUTES');
  }

  return {
    nodeEnv: parsed.NODE_ENV,
    logLevel: parsed.LOG_LEVEL,
    primaryDomain: parsed.PRIMARY_DOMAIN.toLowerCase(),
    mailHostname: parsed.MAIL_HOSTNAME.toLowerCase(),
    allowedDomains: parsed.ALLOWED_DOMAINS,
    smtpPort,
    apiPort: parsed.API_PORT,
    redisUrl: parsed.REDIS_URL,
    databaseUrl: parsed.DATABASE_URL,
    rspamdUrl: parsed.RSPAMD_URL,
    dnsResolver: parsed.DNS_RESOLVER,
    defaultTtlMinutes: parsed.DEFAULT_TTL_MINUTES,
    maxTtlMinutes: parsed.MAX_TTL_MINUTES,
    maxMessageBytes: parsed.MAX_MESSAGE_BYTES,
    maxMessagesPerInbox: parsed.MAX_MESSAGES_PER_INBOX,
    smtpMaxClients: parsed.SMTP_MAX_CLIENTS,
    smtpMaxConnectionsPerIp: parsed.SMTP_MAX_CONNECTIONS_PER_IP,
    smtpMaxRecipients: parsed.SMTP_MAX_RECIPIENTS,
    smtpMaxMessagesPerMin: parsed.SMTP_MAX_MESSAGES_PER_MIN,
    rspamdRejectScore: parsed.RSPAMD_REJECT_SCORE,
    rspamdFlagScore: parsed.RSPAMD_FLAG_SCORE,
    dnsblZones: parsed.DNSBL_ZONES,
    corsOrigins,
    apiRateLimitPerMin: parsed.API_RATE_LIMIT_PER_MIN,
    inboxCreateLimitPerHour: parsed.INBOX_CREATE_LIMIT_PER_HOUR,
    turnstileSecret: parsed.TURNSTILE_SECRET,
    adminApiKey: parsed.ADMIN_API_KEY,
    tlsKeyPath: parsed.TLS_KEY_PATH,
    tlsCertPath: parsed.TLS_CERT_PATH,
    appBaseUrl,
    smtpOutboundHost: parsed.SMTP_OUTBOUND_HOST,
    smtpOutboundPort: parsed.SMTP_OUTBOUND_PORT,
    smtpOutboundSecure: parsed.SMTP_OUTBOUND_SECURE,
    smtpOutboundUser: parsed.SMTP_OUTBOUND_USER,
    smtpOutboundPass: parsed.SMTP_OUTBOUND_PASS,
    smtpOutboundFrom: parsed.SMTP_OUTBOUND_FROM,
    googleClientId: parsed.GOOGLE_CLIENT_ID,
    googleClientSecret: parsed.GOOGLE_CLIENT_SECRET,
    googleRedirectUri:
      parsed.GOOGLE_REDIRECT_URI ||
      (parsed.NODE_ENV === 'production'
        ? `https://api.${parsed.PRIMARY_DOMAIN.toLowerCase()}/api/v1/auth/google/callback`
        : `http://localhost:${parsed.API_PORT}/api/v1/auth/google/callback`),
    totpEncryptionKey:
      parsed.TOTP_ENCRYPTION_KEY ||
      (parsed.NODE_ENV === 'production'
        ? ''
        : '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
  };
}
