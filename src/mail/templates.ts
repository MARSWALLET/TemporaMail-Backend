export interface EmailTemplateDataMap {
  readonly verify_email: {
    readonly verifyUrl: string;
    readonly expiresHours: number;
  };
  readonly reset_password: {
    readonly resetUrl: string;
    readonly expiresMinutes: number;
  };
  readonly change_email: {
    readonly confirmUrl: string;
    readonly newEmail: string;
    readonly expiresHours: number;
  };
  readonly new_login_alert: {
    readonly ip: string;
    readonly userAgent: string;
    readonly time: string;
  };
  readonly '2fa_enabled': {
    readonly time: string;
  };
  readonly '2fa_changed': {
    readonly action: string;
    readonly time: string;
  };
  readonly password_changed: {
    readonly time: string;
  };
  readonly api_key_created: {
    readonly keyName: string;
    readonly keyPrefix: string;
    readonly scopes: readonly string[];
    readonly time: string;
  };
  readonly admin_login_alert: {
    readonly adminEmail: string;
    readonly ip: string;
    readonly reason: string;
    readonly time: string;
  };
}

export type EmailTemplateName = keyof EmailTemplateDataMap;

export interface RenderedEmail {
  readonly subject: string;
  readonly text: string;
  readonly html: string;
}

export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function wrapHtml(title: string, bodyHtml: string): string {
  return [
    '<!doctype html>',
    '<html lang="en">',
    '<body style="font-family:system-ui,-apple-system,sans-serif;color:#111827;line-height:1.5;max-width:600px;margin:0 auto;padding:24px;">',
    `<h2 style="margin:0 0 16px 0;">${escapeHtml(title)}</h2>`,
    bodyHtml,
    '<hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;" />',
    '<p style="font-size:12px;color:#6b7280;">TemporaMail Security &amp; Account Notifications. Do not reply to this email.</p>',
    '</body>',
    '</html>',
  ].join('');
}

export function renderEmailTemplate<T extends EmailTemplateName>(
  template: T,
  data: EmailTemplateDataMap[T],
): RenderedEmail {
  switch (template) {
    case 'verify_email': {
      const d = data as EmailTemplateDataMap['verify_email'];
      const safeUrl = escapeHtml(d.verifyUrl);
      return {
        subject: 'Verify your TemporaMail email address',
        text: `Verify your TemporaMail account by opening this link (valid for ${d.expiresHours} hours):\n\n${d.verifyUrl}\n\nIf you did not sign up, you can safely ignore this email.`,
        html: wrapHtml(
          'Verify your email address',
          `<p>Click the link below to verify your TemporaMail account. This link expires in ${d.expiresHours} hours.</p>` +
            `<p><a href="${safeUrl}" style="display:inline-block;padding:10px 16px;background:#111827;color:#ffffff;text-decoration:none;border-radius:6px;">Verify Email</a></p>` +
            `<p style="font-size:12px;word-break:break-all;">Or copy this URL: ${safeUrl}</p>`,
        ),
      };
    }

    case 'reset_password': {
      const d = data as EmailTemplateDataMap['reset_password'];
      const safeUrl = escapeHtml(d.resetUrl);
      return {
        subject: 'Reset your TemporaMail password',
        text: `Reset your TemporaMail password using this single-use link (expires in ${d.expiresMinutes} minutes):\n\n${d.resetUrl}\n\nIf you did not request a password reset, ignore this email.`,
        html: wrapHtml(
          'Reset your password',
          `<p>We received a request to reset your TemporaMail password. This single-use link expires in ${d.expiresMinutes} minutes.</p>` +
            `<p><a href="${safeUrl}" style="display:inline-block;padding:10px 16px;background:#111827;color:#ffffff;text-decoration:none;border-radius:6px;">Reset Password</a></p>` +
            `<p style="font-size:12px;word-break:break-all;">Or copy this URL: ${safeUrl}</p>`,
        ),
      };
    }

    case 'change_email': {
      const d = data as EmailTemplateDataMap['change_email'];
      const safeUrl = escapeHtml(d.confirmUrl);
      const safeEmail = escapeHtml(d.newEmail);
      return {
        subject: 'Confirm your new TemporaMail email address',
        text: `Confirm changing your TemporaMail email to ${d.newEmail} (valid for ${d.expiresHours} hours):\n\n${d.confirmUrl}`,
        html: wrapHtml(
          'Confirm email change',
          `<p>Confirm changing your account email to <strong>${safeEmail}</strong> (expires in ${d.expiresHours} hours).</p>` +
            `<p><a href="${safeUrl}">Confirm New Email</a></p>`,
        ),
      };
    }

    case 'new_login_alert': {
      const d = data as EmailTemplateDataMap['new_login_alert'];
      return {
        subject: 'New login to your TemporaMail account',
        text: `A new login occurred on your TemporaMail account.\nTime: ${d.time}\nIP: ${d.ip}\nDevice: ${d.userAgent}\n\nIf this was not you, change your password and log out everywhere immediately.`,
        html: wrapHtml(
          'New login detected',
          `<p>A new login occurred on your TemporaMail account:</p>` +
            `<ul><li><strong>Time:</strong> ${escapeHtml(d.time)}</li><li><strong>IP:</strong> ${escapeHtml(d.ip)}</li><li><strong>Device:</strong> ${escapeHtml(d.userAgent)}</li></ul>` +
            `<p>If this was not you, change your password and log out everywhere immediately.</p>`,
        ),
      };
    }

    case '2fa_enabled': {
      const d = data as EmailTemplateDataMap['2fa_enabled'];
      return {
        subject: 'Two-factor authentication enabled on TemporaMail',
        text: `Two-factor authentication (TOTP) was enabled on your TemporaMail account at ${d.time}. Keep your recovery codes in a safe place.`,
        html: wrapHtml(
          'Two-factor authentication enabled',
          `<p>Two-factor authentication (TOTP) was enabled on your account at <strong>${escapeHtml(d.time)}</strong>.</p><p>Keep your recovery codes stored securely.</p>`,
        ),
      };
    }

    case '2fa_changed': {
      const d = data as EmailTemplateDataMap['2fa_changed'];
      return {
        subject: 'Two-factor authentication settings updated',
        text: `Your TemporaMail 2FA settings were updated (${d.action}) at ${d.time}. If you did not do this, secure your account immediately.`,
        html: wrapHtml(
          'Two-factor authentication updated',
          `<p>Action: <strong>${escapeHtml(d.action)}</strong> at ${escapeHtml(d.time)}.</p><p>If you did not make this change, secure your account immediately.</p>`,
        ),
      };
    }

    case 'password_changed': {
      const d = data as EmailTemplateDataMap['password_changed'];
      return {
        subject: 'Your TemporaMail password was changed',
        text: `Your TemporaMail account password was changed at ${d.time}. If you did not make this change, reset your password immediately.`,
        html: wrapHtml(
          'Password changed',
          `<p>Your TemporaMail password was changed at <strong>${escapeHtml(d.time)}</strong>.</p><p>If this was not you, reset your password immediately.</p>`,
        ),
      };
    }

    case 'api_key_created': {
      const d = data as EmailTemplateDataMap['api_key_created'];
      const scopeList = d.scopes.join(', ');
      return {
        subject: `New TemporaMail API key created: ${d.keyName}`,
        text: `A new API key was created on your TemporaMail account.\nName: ${d.keyName}\nPrefix: ${d.keyPrefix}\nScopes: ${scopeList}\nTime: ${d.time}\n\nIf you did not create this key, revoke it immediately.`,
        html: wrapHtml(
          'New API key created',
          `<p>A new API key was created on your account:</p>` +
            `<ul><li><strong>Name:</strong> ${escapeHtml(d.keyName)}</li><li><strong>Prefix:</strong> <code>${escapeHtml(d.keyPrefix)}</code></li><li><strong>Scopes:</strong> ${escapeHtml(scopeList)}</li><li><strong>Time:</strong> ${escapeHtml(d.time)}</li></ul>` +
            `<p>If you did not create this key, revoke it immediately from your dashboard.</p>`,
        ),
      };
    }

    case 'admin_login_alert': {
      const d = data as EmailTemplateDataMap['admin_login_alert'];
      return {
        subject: `TemporaMail Admin Security Alert: ${d.reason}`,
        text: `Admin security event detected.\nAdmin: ${d.adminEmail}\nReason: ${d.reason}\nIP: ${d.ip}\nTime: ${d.time}`,
        html: wrapHtml(
          'Admin Security Alert',
          `<ul><li><strong>Admin:</strong> ${escapeHtml(d.adminEmail)}</li><li><strong>Reason:</strong> ${escapeHtml(d.reason)}</li><li><strong>IP:</strong> ${escapeHtml(d.ip)}</li><li><strong>Time:</strong> ${escapeHtml(d.time)}</li></ul>`,
        ),
      };
    }
  }
}
