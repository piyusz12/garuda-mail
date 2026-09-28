/**
 * JA4 Signature Database — Known TLS client fingerprints
 * Maps JA4 fingerprint prefixes to known software identification
 */

export const JA4_SIGNATURES = {
  // ═══ Web Browsers ═══
  't13d1516h2': { name: 'Chrome 120+', category: 'browser', vendor: 'Google', risk: 'low', description: 'Standard Google Chrome / Chromium browser' },
  't13d1517h2': { name: 'Chrome 115-119', category: 'browser', vendor: 'Google', risk: 'low', description: 'Google Chrome (older stable)' },
  't13d1715h2': { name: 'Firefox 120+', category: 'browser', vendor: 'Mozilla', risk: 'low', description: 'Mozilla Firefox browser' },
  't13d1614h2': { name: 'Firefox 110-119', category: 'browser', vendor: 'Mozilla', risk: 'low', description: 'Mozilla Firefox (older stable)' },
  't13d1513h2': { name: 'Safari 17+', category: 'browser', vendor: 'Apple', risk: 'low', description: 'Apple Safari on macOS/iOS' },
  't13d1312h2': { name: 'Edge 120+', category: 'browser', vendor: 'Microsoft', risk: 'low', description: 'Microsoft Edge (Chromium-based)' },

  // ═══ Email Clients ═══
  't13d0810h1': { name: 'Thunderbird 115+', category: 'email_client', vendor: 'Mozilla', risk: 'low', description: 'Mozilla Thunderbird email client' },
  't12d0608h1': { name: 'Outlook 365', category: 'email_client', vendor: 'Microsoft', risk: 'low', description: 'Microsoft Outlook 365' },
  't12d0506h1': { name: 'Apple Mail', category: 'email_client', vendor: 'Apple', risk: 'low', description: 'Apple Mail on macOS/iOS' },

  // ═══ Mail Transfer Agents ═══
  't13d0308h0': { name: 'Postfix 3.8+', category: 'mta', vendor: 'Postfix', risk: 'low', description: 'Postfix MTA with modern OpenSSL' },
  't12d0407h0': { name: 'Postfix 3.5', category: 'mta', vendor: 'Postfix', risk: 'low', description: 'Postfix MTA (older config)' },
  't12d0305h0': { name: 'Exim 4.96+', category: 'mta', vendor: 'Exim', risk: 'low', description: 'Exim mail server' },
  't12d0204h0': { name: 'Sendmail 8.17', category: 'mta', vendor: 'Sendmail', risk: 'medium', description: 'Sendmail MTA — check for legacy config' },
  't13d0410h0': { name: 'Exchange 2019', category: 'mta', vendor: 'Microsoft', risk: 'low', description: 'Microsoft Exchange Server 2019' },

  // ═══ Suspicious / Pentesting Tools ═══
  't12d0203h0': { name: 'Python requests', category: 'scripting', vendor: 'Python', risk: 'high', description: 'Python requests/urllib3 library — potential automation or scraping' },
  't12d0102h0': { name: 'Python ssl (default)', category: 'scripting', vendor: 'Python', risk: 'high', description: 'Python ssl module with default settings — common in exfiltration tools' },
  't10d0103h0': { name: 'Python ssl (legacy)', category: 'scripting', vendor: 'Python', risk: 'critical', description: 'Python ssl module forcing TLS 1.0 — likely malicious tool' },
  't12d0305h0_msf': { name: 'Metasploit Framework', category: 'exploit', vendor: 'Rapid7', risk: 'critical', description: 'Metasploit exploitation framework' },
  't12d0204h0_hyd': { name: 'Hydra', category: 'exploit', vendor: 'THC', risk: 'critical', description: 'THC Hydra brute-force tool' },
  't12d0102h0_nkto': { name: 'Nikto', category: 'scanner', vendor: 'CIRT', risk: 'high', description: 'Nikto web vulnerability scanner' },
  't12d0204h0_nmap': { name: 'Nmap NSE', category: 'scanner', vendor: 'Nmap', risk: 'high', description: 'Nmap scripting engine — network scanning activity' },
  't12d0103h0_go': { name: 'Go crypto/tls', category: 'scripting', vendor: 'Go', risk: 'medium', description: 'Go language TLS stack — potential custom tool' },
  't12d0102h0_curl': { name: 'curl/libcurl', category: 'utility', vendor: 'curl', risk: 'medium', description: 'curl CLI — could be legitimate or automation' },
  't12d0102h0_wget': { name: 'wget', category: 'utility', vendor: 'GNU', risk: 'medium', description: 'GNU wget — automated download tool' },

  // ═══ Bots / Malware families ═══
  't10d0102h0_rat': { name: 'Generic RAT (TLS 1.0)', category: 'malware', vendor: 'Unknown', risk: 'critical', description: 'Remote Access Trojan using obsolete TLS 1.0' },
  't12d0103h0_c2': { name: 'C2 Beacon Pattern', category: 'malware', vendor: 'Unknown', risk: 'critical', description: 'Command & Control beacon pattern — uniform timing + minimal ciphers' },
  't12d0204h0_cob': { name: 'Cobalt Strike', category: 'malware', vendor: 'Fortra', risk: 'critical', description: 'Cobalt Strike adversary simulation / commonly abused by threat actors' },
  't12d0103h0_emo': { name: 'Emotet Loader', category: 'malware', vendor: 'Unknown', risk: 'critical', description: 'Emotet malware loader network signature' },
};

/**
 * Match a JA4 fingerprint against the database
 */
export function matchJA4(fingerprint) {
  if (!fingerprint) return null;

  // Exact match
  if (JA4_SIGNATURES[fingerprint]) {
    return JA4_SIGNATURES[fingerprint];
  }

  // Prefix match (first segment)
  const prefix = fingerprint.split('_')[0];
  for (const [key, value] of Object.entries(JA4_SIGNATURES)) {
    if (key.startsWith(prefix)) {
      return { ...value, matchType: 'prefix' };
    }
  }

  return null;
}

/**
 * Categorize a JA4 fingerprint
 */
export function categorizeJA4(fingerprint) {
  const match = matchJA4(fingerprint);
  if (!match) return 'unknown';
  if (match.category === 'malware' || match.category === 'exploit') return 'suspicious';
  return 'known';
}
