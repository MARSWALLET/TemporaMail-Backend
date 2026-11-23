import pino, { type Logger } from 'pino';

export function createLogger(name: string, level: string = 'info', nodeEnv: string = 'development'): Logger {
  const baseOptions: pino.LoggerOptions = {
    name,
    level: nodeEnv === 'test' ? 'silent' : level,
  };

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
