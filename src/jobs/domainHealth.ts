import { X509Certificate } from 'node:crypto';
import dns from 'node:dns/promises';
import { readFileSync } from 'node:fs';
import type { Logger } from 'pino';

export interface DomainHealthReport {
  readonly mailHostname: string;
  readonly mailHostnameResolved: boolean;
  readonly domains: ReadonlyArray<{
    readonly domain: string;
    readonly mxValid: boolean;
    readonly mxRecords: readonly string[];
  }>;
  readonly tlsCertDaysRemaining: number | null;
  readonly tlsCertExpiringSoon: boolean;
}

export interface DomainHealthDeps {
  readonly mailHostname: string;
  readonly domains: readonly string[];
  readonly tlsCertPath?: string;
  readonly tlsWarnDays?: number;
  readonly resolveMx?: (domain: string) => Promise<Array<{ exchange: string; priority: number }>>;
  readonly resolveHost?: (hostname: string) => Promise<string[]>;
  readonly readCertPem?: (path: string) => Buffer;
}

const DEFAULT_TLS_WARN_DAYS = 14;

export async function runDomainHealthCheck(
  deps: DomainHealthDeps,
  logger: Logger,
): Promise<DomainHealthReport> {
  const resolveMx = deps.resolveMx ?? ((d: string) => dns.resolveMx(d));
  const resolveHost = deps.resolveHost ?? ((h: string) => dns.resolve4(h));
  const readCertPem = deps.readCertPem ?? ((p: string) => readFileSync(p));
  const warnDays = deps.tlsWarnDays ?? DEFAULT_TLS_WARN_DAYS;
  const targetHost = deps.mailHostname.toLowerCase();

  let mailHostnameResolved = false;
  try {
    const ips = await resolveHost(targetHost);
    mailHostnameResolved = ips.length > 0;
  } catch (err) {
    logger.warn({ err, mailHostname: targetHost }, 'Mail hostname failed DNS resolution');
  }

  const domainReports: Array<{
    domain: string;
    mxValid: boolean;
    mxRecords: string[];
  }> = [];

  for (const domain of deps.domains) {
    try {
      const records = await resolveMx(domain);
      const exchanges = records.map((r) => r.exchange.toLowerCase().replace(/\.$/, ''));
      const mxValid = exchanges.includes(targetHost);
      if (!mxValid) {
        logger.warn(
          { domain, expectedMx: targetHost, actualMx: exchanges },
          'Domain MX record does not point to MAIL_HOSTNAME',
        );
      }
      domainReports.push({ domain, mxValid, mxRecords: exchanges });
    } catch (err) {
      logger.warn({ err, domain }, 'Failed to resolve MX records for domain');
      domainReports.push({ domain, mxValid: false, mxRecords: [] });
    }
  }

  let tlsCertDaysRemaining: number | null = null;
  let tlsCertExpiringSoon = false;

  if (deps.tlsCertPath) {
    try {
      const pem = readCertPem(deps.tlsCertPath);
      const cert = new X509Certificate(pem);
      const validToMs = Date.parse(cert.validTo);
      if (!Number.isNaN(validToMs)) {
        tlsCertDaysRemaining = Math.floor((validToMs - Date.now()) / (24 * 60 * 60 * 1000));
        tlsCertExpiringSoon = tlsCertDaysRemaining <= warnDays;
        if (tlsCertExpiringSoon) {
          logger.warn(
            {
              tlsCertPath: deps.tlsCertPath,
              daysRemaining: tlsCertDaysRemaining,
              validTo: cert.validTo,
            },
            'TLS certificate is expiring soon',
          );
        }
      }
    } catch (err) {
      logger.warn({ err, tlsCertPath: deps.tlsCertPath }, 'Failed to inspect TLS certificate');
    }
  }

  const report: DomainHealthReport = {
    mailHostname: targetHost,
    mailHostnameResolved,
    domains: domainReports,
    tlsCertDaysRemaining,
    tlsCertExpiringSoon,
  };

  logger.info({ report }, 'Daily domain health check finished');
  return report;
}
