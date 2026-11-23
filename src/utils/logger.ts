import pino, { type DestinationStream, type Logger } from 'pino';

export const LOG_REDACT_PATHS: readonly string[] = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-owner-token"]',
  'req.headers["x-admin-api-key"]',
  'headers.authorization',
  'headers.cookie',
  'password',
  'newPassword',
  'currentPassword',
  'passwordHash',
  'token',
  'mfaToken',
  'ownerToken',
  'apiKey',
  'key',
  'secret',
  'totpSecret',
  'recoveryCodes',
  '*.password',
  '*.newPassword',
  '*.currentPassword',
  '*.passwordHash',
  '*.token',
  '*.mfaToken',
  '*.ownerToken',
  '*.apiKey',
  '*.secret',
  '*.totpSecret',
  '*.recoveryCodes',
];

export function createLogger(
  name: string,
  level: string = 'info',
  nodeEnv: string = 'development',
  destination?: DestinationStream,
): Logger {
  const baseOptions: pino.LoggerOptions = {
    name,
    level: nodeEnv === 'test' && !destination ? 'silent' : level,
    redact: {
      paths: [...LOG_REDACT_PATHS],
      censor: '[REDACTED]',
    },
  };

  if (destination) {
    return pino(baseOptions, destination);
  }

  if (nodeEnv === 'development') {
    return pino({
      ...baseOptions,
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
        },
      },
    });
  }

  return pino(baseOptions);
}
