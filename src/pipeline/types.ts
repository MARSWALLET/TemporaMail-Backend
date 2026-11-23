export interface StoredAttachmentMetadata {
  readonly index: number;
  readonly filename: string;
  readonly contentType: string;
  readonly size: number;
}

export interface StoredMessage {
  readonly id: string;
  readonly from: string;
  readonly to: readonly string[];
  readonly subject: string;
  readonly date: string;
  readonly text: string;
  readonly html: string;
  readonly hasRemoteContent: boolean;
  readonly otp: string | null;
  readonly links: readonly string[];
  readonly attachments: readonly StoredAttachmentMetadata[];
  readonly spamScore: number;
  readonly spamFlagged: boolean;
}

export interface SpamCheckInput {
  readonly raw: Buffer;
  readonly remoteAddress: string;
  readonly mailFrom: string;
  readonly rcptTo: readonly string[];
  readonly subject: string;
  readonly text: string;
}

export interface SpamCheckResult {
  readonly action: 'accept' | 'flag' | 'reject';
  readonly score: number;
  readonly reason?: string;
}

export type SpamChecker = (input: SpamCheckInput) => Promise<SpamCheckResult>;
