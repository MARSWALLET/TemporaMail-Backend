import nodemailer, { type Transporter } from 'nodemailer';
import type { Logger } from 'pino';
import type { EnvConfig } from '../config/env.js';
import {
  renderEmailTemplate,
  type EmailTemplateDataMap,
  type EmailTemplateName,
} from './templates.js';

export interface SendEmailResult {
  readonly messageId: string;
}

export interface Mailer {
  sendEmail<T extends EmailTemplateName>(
    to: string,
    template: T,
    data: EmailTemplateDataMap[T],
  ): Promise<SendEmailResult>;
  close(): void;
}

export interface CreateMailerDeps {
  readonly config: EnvConfig;
  readonly logger: Logger;
  /** Optional custom Nodemailer transporter (useful for tests or custom SMTP setups). */
  readonly transporter?: Transporter;
}

/**
 * Outbound-only transactional email sender using user-configured SMTP.
 * Completely separate from the receive-only inbound SMTP server.
 */
export function createMailer(deps: CreateMailerDeps): Mailer {
  const { config, logger } = deps;

  let transporter: Transporter;
  if (deps.transporter) {
    transporter = deps.transporter;
  } else if (config.smtpOutboundHost) {
    transporter = nodemailer.createTransport({
      host: config.smtpOutboundHost,
      port: config.smtpOutboundPort,
      secure: config.smtpOutboundSecure,
      ...(config.smtpOutboundUser
        ? {
            auth: {
              user: config.smtpOutboundUser,
              pass: config.smtpOutboundPass,
            },
          }
        : {}),
    });
  } else {
    // Safe fallback for local dev/test when SMTP_OUTBOUND_HOST is not set
    transporter = nodemailer.createTransport({
      jsonTransport: true,
    });
  }

  return {
    async sendEmail<T extends EmailTemplateName>(
      to: string,
      template: T,
      data: EmailTemplateDataMap[T],
    ): Promise<SendEmailResult> {
      const rendered = renderEmailTemplate(template, data);

      const info = await transporter.sendMail({
        from: config.smtpOutboundFrom,
        to,
        subject: rendered.subject,
        text: rendered.text,
        html: rendered.html,
      });

      const messageId = typeof info.messageId === 'string' ? info.messageId : '';

      // Security: never log email body, tokens, or reset/verify URLs
      logger.info(
        {
          to,
          template,
          messageId,
          transport: config.smtpOutboundHost ? 'smtp' : 'json_dev',
        },
        'Transactional email dispatched',
      );

      return { messageId };
    },

    close(): void {
      transporter.close();
    },
  };
}
