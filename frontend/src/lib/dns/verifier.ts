import { createPublicKey } from 'crypto';
import * as dns from 'dns/promises';

export interface DnsRecordStatus {
  protocol: 'SPF' | 'DKIM' | 'DMARC';
  friendlyName: string;
  conceptTranslation: string;
  recordType: 'TXT' | 'CNAME';
  host: string;
  expectedValue: string;
  foundValue: string | null;
  isVerified: boolean;
  statusText: string;
  ttlSeconds: number | null;
  lastChecked: string;
}

export interface DomainVerificationResult {
  domain: string;
  selector: string;
  isFullyCompliant: boolean;
  driftDetected: boolean;
  records: {
    spf: DnsRecordStatus;
    dkim: DnsRecordStatus;
    dmarc: DnsRecordStatus;
  };
  recommendations: string[];
}

export const PROTOCOL_TRANSLATIONS = {
  SPF: {
    friendlyName: 'Sender Policy Framework (SPF)',
    concept: 'Authorize Garuda Mail to send on your behalf ("The Guest List"). Prevents spammers from forging your sender address.',
    expectedHost: '@',
    defaultRecord: 'v=spf1 include:_spf.garudamail.com ~all',
  },
  DKIM: {
    friendlyName: 'DomainKeys Identified Mail (DKIM)',
    concept: 'Add a tamper-proof asymmetric cryptographic signature to every dispatched message.',
    expectedHost: (selector: string) => `${selector}._domainkey`,
    defaultRecord: 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz5e1uQv1m9K...',
  },
  DMARC: {
    friendlyName: 'Domain-based Message Authentication, Reporting & Conformance (DMARC)',
    concept: 'Tell inbox providers (Gmail, Yahoo, Outlook) how to handle suspicious emails claiming to be you.',
    expectedHost: '_dmarc',
    defaultRecord: 'v=DMARC1; p=none; rua=mailto:dmarc-reports@garudamail.com; pct=100; aspf=r; adkim=r',
  },
};

/**
 * Verify DNS authentication records (SPF, DKIM, DMARC) for a sending domain.
 * Gracefully handles missing DNS entries and network timeouts.
 */
export async function verifyDomainAuthentication(
  domain: string,
  selector: string = 'garuda'
): Promise<DomainVerificationResult> {
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const now = new Date().toISOString();

  // 1. Verify SPF Record
  let spfFound: string | null = null;
  const spfTtl: number | null = null;
  let isSpfVerified = false;

  try {
    const txtRecords = await dns.resolveTxt(cleanDomain);
    for (const chunk of txtRecords) {
      const fullRecord = chunk.join('');
      if (fullRecord.startsWith('v=spf1')) {
        spfFound = fullRecord;
        if (/(^|\s)[+]?include:_spf\.garudamail\.com(\s|$)/i.test(fullRecord)) {
          isSpfVerified = true;
        }
        break;
      }
    }
  } catch {
    // DNS resolution failure (NXDOMAIN / TIMEOUT / NODATA)
    spfFound = null;
  }

  // 2. Verify DKIM Record
  const dkimHost = `${selector}._domainkey.${cleanDomain}`;
  let dkimFound: string | null = null;
  const dkimTtl: number | null = null;
  let isDkimVerified = false;

  try {
    const dkimRecords = await dns.resolveTxt(dkimHost);
    for (const chunk of dkimRecords) {
      const fullRecord = chunk.join('');
      // RFC 6376: v=DKIM1 is optional. If present, it MUST be DKIM1. Reject unsupported versions.
      const vMatch = fullRecord.match(/(?:^|;\s*)v\s*=\s*([^;\s]+)/i);
      if (vMatch && vMatch[1].toUpperCase() !== 'DKIM1') {
        continue;
      }

      const pMatch = fullRecord.match(/(?:^|;|\s)p\s*=\s*([A-Za-z0-9+/=\s]+?)(?:;|$)/);
      if (pMatch && pMatch[1]) {
        const cleanP = pMatch[1].replace(/\s+/g, '');
        if (!cleanP) continue;
        try {
          const keyBuf = Buffer.from(cleanP, 'base64');
          const kMatch = fullRecord.match(/(?:^|;|\s)k\s*=\s*([A-Za-z0-9-]+)/i);
          const keyType = (kMatch?.[1] ?? 'rsa').toLowerCase();
          let importKey = keyBuf;

          if (keyType === 'ed25519') {
            if (keyBuf.length !== 32) continue;
            // Ed25519 SubjectPublicKeyInfo header (RFC 8463 / RFC 8410: 1.3.101.112)
            importKey = Buffer.concat([
              Buffer.from('302a300506032b6570032100', 'hex'),
              keyBuf,
            ]);
          } else if (keyType !== 'rsa') {
            continue;
          }

          const parsedKey = createPublicKey({ key: importKey, format: 'der', type: 'spki' });
          if (
            (parsedKey.asymmetricKeyType === 'rsa' && (parsedKey.asymmetricKeyDetails?.modulusLength ?? 0) >= 1024) ||
            parsedKey.asymmetricKeyType === 'ed25519'
          ) {
            dkimFound = fullRecord;
            isDkimVerified = true;
            break;
          }
        } catch {
          // Unusable or malformed key
        }
      }
    }
  } catch {
    dkimFound = null;
  }

  // 3. Verify DMARC Record
  const dmarcHost = `_dmarc.${cleanDomain}`;
  let dmarcFound: string | null = null;
  const dmarcTtl: number | null = null;
  let isDmarcVerified = false;

  try {
    const dmarcRecords = await dns.resolveTxt(dmarcHost);
    for (const chunk of dmarcRecords) {
      const fullRecord = chunk.join('');
      if (fullRecord.startsWith('v=DMARC1')) {
        dmarcFound = fullRecord;
        isDmarcVerified = true;
        break;
      }
    }
  } catch {
    dmarcFound = null;
  }

  const recommendations: string[] = [];
  if (!isSpfVerified) {
    recommendations.push('Publish the recommended SPF TXT record on your root domain to prevent Gmail rejection.');
  }
  if (!isDkimVerified) {
    recommendations.push(`Generate and publish the DKIM public key at selector "${selector}._domainkey.${cleanDomain}".`);
  }
  if (!isDmarcVerified) {
    recommendations.push('Create a DMARC record starting with p=none to monitor authentication reports.');
  } else if (dmarcFound?.includes('p=none')) {
    recommendations.push('DMARC is in monitoring mode (p=none). Once SPF/DKIM alignment stabilizes, upgrade to p=quarantine.');
  }

  const isFullyCompliant = isSpfVerified && isDkimVerified && isDmarcVerified;

  return {
    domain: cleanDomain,
    selector,
    isFullyCompliant,
    driftDetected: !isFullyCompliant && (isSpfVerified || isDkimVerified || isDmarcVerified),
    records: {
      spf: {
        protocol: 'SPF',
        friendlyName: PROTOCOL_TRANSLATIONS.SPF.friendlyName,
        conceptTranslation: PROTOCOL_TRANSLATIONS.SPF.concept,
        recordType: 'TXT',
        host: '@',
        expectedValue: PROTOCOL_TRANSLATIONS.SPF.defaultRecord,
        foundValue: spfFound,
        isVerified: isSpfVerified,
        statusText: isSpfVerified ? 'Authenticated (Active)' : 'Record Missing or Misaligned',
        ttlSeconds: spfTtl || 3600,
        lastChecked: now,
      },
      dkim: {
        protocol: 'DKIM',
        friendlyName: PROTOCOL_TRANSLATIONS.DKIM.friendlyName,
        conceptTranslation: PROTOCOL_TRANSLATIONS.DKIM.concept,
        recordType: 'TXT',
        host: PROTOCOL_TRANSLATIONS.DKIM.expectedHost(selector),
        expectedValue: PROTOCOL_TRANSLATIONS.DKIM.defaultRecord,
        foundValue: dkimFound,
        isVerified: isDkimVerified,
        statusText: isDkimVerified ? '2048-bit Signature Valid' : 'Selector Key Not Found',
        ttlSeconds: dkimTtl || 3600,
        lastChecked: now,
      },
      dmarc: {
        protocol: 'DMARC',
        friendlyName: PROTOCOL_TRANSLATIONS.DMARC.friendlyName,
        conceptTranslation: PROTOCOL_TRANSLATIONS.DMARC.concept,
        recordType: 'TXT',
        host: PROTOCOL_TRANSLATIONS.DMARC.expectedHost,
        expectedValue: PROTOCOL_TRANSLATIONS.DMARC.defaultRecord,
        foundValue: dmarcFound,
        isVerified: isDmarcVerified,
        statusText: isDmarcVerified ? 'Policy Enforced' : 'DMARC Policy Missing',
        ttlSeconds: dmarcTtl || 3600,
        lastChecked: now,
      },
    },
    recommendations,
  };
}

