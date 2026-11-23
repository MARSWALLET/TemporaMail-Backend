export interface OtpAndLinksResult {
  readonly otp: string | null;
  readonly links: readonly string[];
}

const OTP_KEYWORDS =
  '(?:verification\\s+code|security\\s+code|confirmation\\s+code|login\\s+code|sign[- ]?in\\s+code|one[- ]?time\\s+(?:password|passcode|code)|otp|passcode|pin\\s+code|auth\\s+code|code|pin|token)';

// Keyword followed by 4-8 digits (allowing short connector words like "is", ":", "-", etc.)
const KEYWORD_BEFORE_OTP = new RegExp(
  `\\b${OTP_KEYWORDS}\\b[^\\d\\n]{0,35}(?<![\\d-])(\\d{4,8})(?![\\d-])`,
  'i',
);

// 4-8 digits followed closely by keyword (e.g., "482910 is your verification code")
const OTP_BEFORE_KEYWORD = new RegExp(
  `(?<![\\d-])(\\d{4,8})(?![\\d-])[^\\d\\n]{0,35}\\b${OTP_KEYWORDS}\\b`,
  'i',
);

const URL_REGEX = /https?:\/\/[^\s"'<>)\]]+/gi;
const VERIFICATION_LINK_KEYWORD =
  /(?:verify|verif|confirm|activate|activation|validate|validation|reset[-_]?password|magic[-_]?link|accept[-_]?invite|auth\/verify|email[-_]?confirm)/i;

const ANCHOR_REGEX = /<a\b[^>]*\bhref\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

function cleanTrailingPunctuation(url: string): string {
  return url.replace(/[.,;:!?]+$/, '');
}

function stripHtmlTags(html: string): string {
  return html
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function detectOtp(subject: string, text: string, html: string | null): string | null {
  const candidates = [subject, text, html ? stripHtmlTags(html) : ''];

  for (const content of candidates) {
    if (!content) {
      continue;
    }

    const beforeMatch = KEYWORD_BEFORE_OTP.exec(content);
    if (beforeMatch?.[1]) {
      return beforeMatch[1];
    }

    const afterMatch = OTP_BEFORE_KEYWORD.exec(content);
    if (afterMatch?.[1]) {
      return afterMatch[1];
    }
  }

  return null;
}

export function detectVerificationLinks(
  text: string,
  html: string | null,
  maxLinks: number = 10,
): readonly string[] {
  const found = new Set<string>();

  const collectFromText = (source: string): void => {
    const matches = source.match(URL_REGEX);
    if (!matches) {
      return;
    }
    for (const rawUrl of matches) {
      const cleaned = cleanTrailingPunctuation(rawUrl);
      if (VERIFICATION_LINK_KEYWORD.test(cleaned)) {
        found.add(cleaned);
        if (found.size >= maxLinks) {
          return;
        }
      }
    }
  };

  collectFromText(text);

  if (html && found.size < maxLinks) {
    let match: RegExpExecArray | null;
    ANCHOR_REGEX.lastIndex = 0;
    while ((match = ANCHOR_REGEX.exec(html)) !== null) {
      const href = match[1] ? cleanTrailingPunctuation(match[1]) : '';
      const anchorText = match[2] ? stripHtmlTags(match[2]) : '';
      if (href && (VERIFICATION_LINK_KEYWORD.test(href) || VERIFICATION_LINK_KEYWORD.test(anchorText))) {
        found.add(href);
        if (found.size >= maxLinks) {
          break;
        }
      }
    }

    if (found.size < maxLinks) {
      collectFromText(html);
    }
  }

  return Array.from(found);
}

export function extractOtpAndLinks(
  subject: string,
  text: string,
  html: string | null,
): OtpAndLinksResult {
  return {
    otp: detectOtp(subject, text, html),
    links: detectVerificationLinks(text, html),
  };
}
