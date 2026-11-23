import path from 'node:path';
import type { Attachment } from 'mailparser';
import type { StoredAttachmentMetadata } from './types.js';

export const BLOCKED_ATTACHMENT_EXTENSIONS: ReadonlySet<string> = new Set([
  '.exe',
  '.scr',
  '.bat',
  '.cmd',
  '.js',
  '.vbs',
  '.ps1',
  '.jar',
  '.msi',
  '.com',
]);

export interface AcceptedAttachment {
  readonly metadata: StoredAttachmentMetadata;
  readonly content: Buffer;
}

export interface RejectedAttachment {
  readonly filename: string;
  readonly reason: 'blocked_extension' | 'size_limit_exceeded';
}

export interface FilterAttachmentsResult {
  readonly accepted: readonly AcceptedAttachment[];
  readonly rejected: readonly RejectedAttachment[];
}

export function sanitizeFilename(rawName: string | undefined, fallbackIndex: number): string {
  const base = rawName ? path.basename(rawName).trim() : '';
  const cleaned = base.replace(/[\r\n\0/\\]+/g, '_');
  return cleaned.length > 0 ? cleaned.slice(0, 200) : `attachment-${fallbackIndex}`;
}

export function isBlockedExtension(filename: string): boolean {
  const ext = path.extname(filename).toLowerCase();
  return BLOCKED_ATTACHMENT_EXTENSIONS.has(ext);
}

export function filterAttachments(
  attachments: readonly Attachment[],
  maxTotalBytes: number,
): FilterAttachmentsResult {
  const accepted: AcceptedAttachment[] = [];
  const rejected: RejectedAttachment[] = [];
  let totalBytes = 0;

  for (let i = 0; i < attachments.length; i += 1) {
    const att = attachments[i];
    if (!att) {
      continue;
    }

    const filename = sanitizeFilename(att.filename, i);

    if (isBlockedExtension(filename)) {
      rejected.push({ filename, reason: 'blocked_extension' });
      continue;
    }

    const content = Buffer.isBuffer(att.content) ? att.content : Buffer.from(att.content);
    const size = content.length;

    if (totalBytes + size > maxTotalBytes) {
      rejected.push({ filename, reason: 'size_limit_exceeded' });
      continue;
    }

    totalBytes += size;
    const index = accepted.length;
    accepted.push({
      metadata: {
        index,
        filename,
        contentType: att.contentType || 'application/octet-stream',
        size,
      },
      content,
    });
  }

  return { accepted, rejected };
}
