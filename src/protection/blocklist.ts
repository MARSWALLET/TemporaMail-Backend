import { extractDomain, normalizeAddress } from '../utils/address.js';

export type BlocklistEntryType = 'sender' | 'domain' | 'ip' | 'keyword';

export interface BlocklistEntry {
  readonly type: BlocklistEntryType;
  readonly value: string;
  readonly reason?: string;
}

export interface BlocklistCheckInput {
  readonly ip: string;
  readonly mailFrom: string;
  readonly subject: string;
  readonly text: string;
}

export interface BlocklistMatch {
  readonly matched: boolean;
  readonly type?: BlocklistEntryType;
  readonly value?: string;
  readonly reason?: string;
}

/**
 * In-memory blocklist cache refreshed periodically from PostgreSQL (Step 6).
 */
export class BlocklistStore {
  private senders = new Map<string, string>();
  private domains = new Map<string, string>();
  private ips = new Map<string, string>();
  private keywords: Array<{ value: string; reason: string }> = [];

  constructor(initialEntries: readonly BlocklistEntry[] = []) {
    this.update(initialEntries);
  }

  update(entries: readonly BlocklistEntry[]): void {
    const nextSenders = new Map<string, string>();
    const nextDomains = new Map<string, string>();
    const nextIps = new Map<string, string>();
    const nextKeywords: Array<{ value: string; reason: string }> = [];

    for (const entry of entries) {
      const value = entry.value.trim().toLowerCase();
      if (!value) {
        continue;
      }
      const reason = entry.reason?.trim() || `blocklist_${entry.type}`;

      switch (entry.type) {
        case 'sender':
          nextSenders.set(value, reason);
          break;
        case 'domain':
          nextDomains.set(value, reason);
          break;
        case 'ip':
          nextIps.set(value, reason);
          break;
        case 'keyword':
          nextKeywords.push({ value, reason });
          break;
      }
    }

    this.senders = nextSenders;
    this.domains = nextDomains;
    this.ips = nextIps;
    this.keywords = nextKeywords;
  }

  checkIp(ip: string): BlocklistMatch {
    const normalized = ip.trim().toLowerCase().replace(/^::ffff:/, '');
    const reason = this.ips.get(normalized);
    if (reason) {
      return { matched: true, type: 'ip', value: normalized, reason };
    }
    return { matched: false };
  }

  checkMessage(input: BlocklistCheckInput): BlocklistMatch {
    const ipMatch = this.checkIp(input.ip);
    if (ipMatch.matched) {
      return ipMatch;
    }

    const sender = normalizeAddress(input.mailFrom);
    if (sender) {
      const senderReason = this.senders.get(sender);
      if (senderReason) {
        return { matched: true, type: 'sender', value: sender, reason: senderReason };
      }

      const domain = extractDomain(sender);
      if (domain) {
        const domainReason = this.domains.get(domain);
        if (domainReason) {
          return { matched: true, type: 'domain', value: domain, reason: domainReason };
        }
      }
    }

    if (this.keywords.length > 0) {
      const haystack = `${input.subject}\n${input.text}`.toLowerCase();
      for (const kw of this.keywords) {
        if (haystack.includes(kw.value)) {
          return { matched: true, type: 'keyword', value: kw.value, reason: kw.reason };
        }
      }
    }

    return { matched: false };
  }
}
