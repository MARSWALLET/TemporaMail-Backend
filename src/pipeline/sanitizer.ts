import sanitizeHtml from 'sanitize-html';

export interface SanitizeHtmlResult {
  readonly html: string;
  readonly hasRemoteContent: boolean;
}

const REMOTE_URL_PATTERN = /^(?:https?:|\/\/)/i;
const CSS_REMOTE_URL_PATTERN = /url\s*\(\s*['"]?\s*(?:https?:|\/\/)/i;

const ALLOWED_TAGS: readonly string[] = [
  'a',
  'abbr',
  'b',
  'blockquote',
  'br',
  'caption',
  'code',
  'col',
  'colgroup',
  'dd',
  'del',
  'div',
  'dl',
  'dt',
  'em',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'hr',
  'i',
  'img',
  'ins',
  'li',
  'mark',
  'ol',
  'p',
  'pre',
  'q',
  's',
  'small',
  'span',
  'strong',
  'sub',
  'sup',
  'table',
  'tbody',
  'td',
  'tfoot',
  'th',
  'thead',
  'tr',
  'u',
  'ul',
];

const DISCARD_CONTENT_TAGS: readonly string[] = [
  'script',
  'style',
  'iframe',
  'object',
  'embed',
  'form',
  'noscript',
  'template',
  'svg',
  'math',
];

export function sanitizeEmailHtml(rawHtml: string): SanitizeHtmlResult {
  if (!rawHtml.trim()) {
    return { html: '', hasRemoteContent: false };
  }

  let hasRemoteContent = false;

  // Detect remote CSS/link/media references before sanitize-html strips disallowed tags
  if (
    /<link\b[^>]*\bhref\s*=\s*['"]?\s*(?:https?:|\/\/)/i.test(rawHtml) ||
    CSS_REMOTE_URL_PATTERN.test(rawHtml) ||
    /<(?:video|audio|source|iframe|embed|object)\b[^>]*\bsrc\s*=\s*['"]?\s*(?:https?:|\/\/)/i.test(
      rawHtml,
    ) ||
    /\bbackground\s*=\s*['"]?\s*(?:https?:|\/\/)/i.test(rawHtml)
  ) {
    hasRemoteContent = true;
  }

  const sanitized = sanitizeHtml(rawHtml, {
    allowedTags: [...ALLOWED_TAGS],
    nonTextTags: [...DISCARD_CONTENT_TAGS],
    allowedAttributes: {
      a: ['href', 'title', 'target', 'rel'],
      img: ['alt', 'title', 'width', 'height'],
      td: ['colspan', 'rowspan', 'align', 'valign'],
      th: ['colspan', 'rowspan', 'align', 'valign'],
      table: ['align', 'width'],
      '*': ['dir', 'lang'],
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesByTag: {
      a: ['http', 'https', 'mailto'],
    },
    allowProtocolRelative: false,
    disallowedTagsMode: 'discard',
    transformTags: {
      a: (tagName, attribs) => {
        const nextAttribs: Record<string, string> = {};
        if (attribs.href) {
          nextAttribs.href = attribs.href;
        }
        if (attribs.title) {
          nextAttribs.title = attribs.title;
        }
        nextAttribs.rel = 'noopener noreferrer nofollow';
        nextAttribs.target = '_blank';
        return { tagName, attribs: nextAttribs };
      },
      img: (tagName, attribs) => {
        const src = attribs.src?.trim() ?? '';
        const srcset = attribs.srcset?.trim() ?? '';
        if (REMOTE_URL_PATTERN.test(src) || REMOTE_URL_PATTERN.test(srcset)) {
          hasRemoteContent = true;
        }

        const nextAttribs: Record<string, string> = {};
        if (attribs.alt) {
          nextAttribs.alt = attribs.alt;
        }
        if (attribs.title) {
          nextAttribs.title = attribs.title;
        }
        if (attribs.width) {
          nextAttribs.width = attribs.width;
        }
        if (attribs.height) {
          nextAttribs.height = attribs.height;
        }
        return { tagName, attribs: nextAttribs };
      },
    },
  });

  return {
    html: sanitized.trim(),
    hasRemoteContent,
  };
}
