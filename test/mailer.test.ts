import nodemailer from 'nodemailer';
import { describe, expect, it, vi } from 'vitest';
import { loadEnv } from '../src/config/env.js';
import { createMailer } from '../src/mail/mailer.js';
import { escapeHtml, renderEmailTemplate } from '../src/mail/templates.js';
import { createLogger } from '../src/utils/logger.js';

const logger = createLogger('mailer-test', 'silent', 'test');

describe('Phase B1: Transactional email templates & outbound SMTP mailer', () => {
  it('escapes HTML special characters in template fields', () => {
    expect(escapeHtml('<script>"alert&1\'</script>')).toBe(
      '&lt;script&gt;&quot;alert&amp;1&#39;&lt;/script&gt;',
    );

    const rendered = renderEmailTemplate('api_key_created', {
      keyName: '<img src=x onerror=alert(1)>',
      keyPrefix: 'tm_live_abc',
      scopes: ['inbox:create', 'messages:read'],
      time: '2026-11-23T12:00:00Z',
    });

    expect(rendered.html).not.toContain('<img src=x');
    expect(rendered.html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(rendered.text).toContain('tm_live_abc');
  });

  it('renders all core account & security templates', () => {
    const verify = renderEmailTemplate('verify_email', {
      verifyUrl: 'https://temporamail.app/verify?token=secret123',
      expiresHours: 24,
    });
    expect(verify.subject).toContain('Verify');
    expect(verify.text).toContain('https://temporamail.app/verify?token=secret123');

    const reset = renderEmailTemplate('reset_password', {
      resetUrl: 'https://temporamail.app/reset-password?token=reset456',
      expiresMinutes: 60,
    });
    expect(reset.subject).toContain('Reset');
    expect(reset.html).toContain('60 minutes');

    const login = renderEmailTemplate('new_login_alert', {
      ip: '203.0.113.10',
      userAgent: 'Mozilla/5.0',
      time: '2026-11-23T12:00:00Z',
    });
    expect(login.text).toContain('203.0.113.10');

    const twoFa = renderEmailTemplate('2fa_enabled', { time: '2026-11-23T12:00:00Z' });
    expect(twoFa.subject).toContain('Two-factor');

    const pwChanged = renderEmailTemplate('password_changed', { time: '2026-11-23T12:00:00Z' });
    expect(pwChanged.subject).toContain('password');
  });

  it('dispatches email via configured transporter with separate sending domain', async () => {
    const config = loadEnv({
      NODE_ENV: 'test',
      SMTP_OUTBOUND_FROM: 'TemporaMail <noreply@account.temporamail.app>',
    });

    const transporter = nodemailer.createTransport({ jsonTransport: true });
    const sendSpy = vi.spyOn(transporter, 'sendMail');

    const mailer = createMailer({ config, logger, transporter });
    const res = await mailer.sendEmail('alice@example.com', 'verify_email', {
      verifyUrl: 'https://temporamail.app/verify?token=tok_abc',
      expiresHours: 24,
    });

    expect(res.messageId.length).toBeGreaterThan(0);
    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(sendSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        from: 'TemporaMail <noreply@account.temporamail.app>',
        to: 'alice@example.com',
        subject: 'Verify your TemporaMail email address',
      }),
    );

    mailer.close();
  });

  it('falls back cleanly to jsonTransport when SMTP_OUTBOUND_HOST is omitted in dev/test', async () => {
    const config = loadEnv({
      NODE_ENV: 'test',
      SMTP_OUTBOUND_HOST: '',
    });

    const mailer = createMailer({ config, logger });
    const res = await mailer.sendEmail('bob@example.com', '2fa_enabled', {
      time: '2026-11-23T12:00:00Z',
    });

    expect(res.messageId.length).toBeGreaterThan(0);
    mailer.close();
  });
});
