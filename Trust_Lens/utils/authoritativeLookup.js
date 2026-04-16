/**
 * authoritativeLookup.js
 * Authoritative DNS & Domain Impersonation Detection
 *
 * This module performs:
 *   1. Authoritative DNS verification via SOA records
 *   2. Domain impersonation detection — if a site's domain contains a known
 *      brand name but isn't the official domain, we look up the REAL domain
 *      and compare identity signals (IPs, NS, registrant, age) to prove
 *      the current site is a spoof.
 *   3. Canonical domain resolution — maps brand names to their official domains
 *   4. Trust comparison scoring — penalizes sites that impersonate known brands
 */

const DOH_BASE = 'https://dns.google/resolve';
const RDAP_BASE = 'https://rdap.org/domain/';
const TIMEOUT_MS = 6000;

// ═══════════════════════════════════════════════════════════════════════
// CANONICAL BRAND → DOMAIN MAP
// If a domain contains one of these brand keywords but ISN'T the canonical
// domain, it's likely an impersonation attempt.
// ═══════════════════════════════════════════════════════════════════════

const BRAND_CANONICAL = {
  // Big Tech
  'paypal':       'paypal.com',
  'google':       'google.com',
  'facebook':     'facebook.com',
  'meta':         'meta.com',
  'apple':        'apple.com',
  'amazon':       'amazon.com',
  'microsoft':    'microsoft.com',
  'netflix':      'netflix.com',
  'instagram':    'instagram.com',
  'twitter':      'twitter.com',
  'x':            'x.com',
  'linkedin':     'linkedin.com',
  'whatsapp':     'whatsapp.com',
  'youtube':      'youtube.com',
  'gmail':        'gmail.com',
  'outlook':      'outlook.com',
  'office365':    'office365.com',
  'dropbox':      'dropbox.com',
  'icloud':       'icloud.com',
  'tiktok':       'tiktok.com',
  'snapchat':     'snapchat.com',
  'telegram':     'telegram.org',
  'discord':      'discord.com',
  'slack':        'slack.com',
  'zoom':         'zoom.us',
  'teams':        'teams.microsoft.com',
  'spotify':      'spotify.com',
  'twitch':       'twitch.tv',
  'reddit':       'reddit.com',
  'pinterest':    'pinterest.com',
  'github':       'github.com',
  'gitlab':       'gitlab.com',
  'steam':        'steampowered.com',
  'epic':         'epicgames.com',

  // Banking & Finance
  'bankofamerica':'bankofamerica.com',
  'chase':        'chase.com',
  'wellsfargo':   'wellsfargo.com',
  'citibank':     'citibank.com',
  'barclays':     'barclays.co.uk',
  'hsbc':         'hsbc.com',
  'sbi':          'onlinesbi.sbi',
  'hdfc':         'hdfcbank.com',
  'icici':        'icicibank.com',
  'paytm':        'paytm.com',
  'phonepe':      'phonepe.com',
  'gpay':         'pay.google.com',
  'jpmorgan':     'jpmorgan.com',
  'goldmansachs': 'goldmansachs.com',
  'capitalone':   'capitalone.com',
  'amex':         'americanexpress.com',
  'americanexpress':'americanexpress.com',
  'discover':     'discover.com',
  'santander':    'santander.com',
  'lloyds':       'lloydsbank.com',
  'natwest':      'natwest.com',
  'halifax':      'halifax.co.uk',

  // Payment & Crypto
  'ebay':         'ebay.com',
  'shopify':      'shopify.com',
  'stripe':       'stripe.com',
  'square':       'squareup.com',
  'venmo':        'venmo.com',
  'cashapp':      'cash.app',
  'coinbase':     'coinbase.com',
  'binance':      'binance.com',
  'kraken':       'kraken.com',
  'blockchain':   'blockchain.com',
  'metamask':     'metamask.io',
  'trustwallet':  'trustwallet.com',
  'opensea':      'opensea.io',

  // eCommerce
  'walmart':      'walmart.com',
  'target':       'target.com',
  'bestbuy':      'bestbuy.com',
  'costco':       'costco.com',
  'alibaba':      'alibaba.com',
  'aliexpress':   'aliexpress.com',
  'etsy':         'etsy.com',

  // Delivery / Shipping
  'fedex':        'fedex.com',
  'ups':          'ups.com',
  'usps':         'usps.com',
  'dhl':          'dhl.com',

  // Security / Auth
  'norton':       'norton.com',
  'mcafee':       'mcafee.com',
  'kaspersky':    'kaspersky.com',
  'avast':        'avast.com',
  'lastpass':     'lastpass.com',
  '1password':    '1password.com',
  'okta':         'okta.com',
  'auth0':        'auth0.com',

  // Government (generic keywords)
  'irs':          'irs.gov',
};

// Known second-level domains for apex extraction
const KNOWN_SLDS = new Set([
  'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil',
  'or', 'ne', 'go', 'gob', 'nic', 'res', 'nhs', 'police', 'govt',
]);

/**
 * Extract the registrable (apex) domain from a hostname.
 */
function getApexDomain(hostname) {
  const parts = hostname.toLowerCase().split('.');
  if (parts.length >= 3 &&
      KNOWN_SLDS.has(parts[parts.length - 2]) &&
      parts[parts.length - 1].length <= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

/**
 * Query Google DoH.
 */
async function queryDNS(domain, type) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const url = `${DOH_BASE}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/dns-json' },
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(timer);
    return null;
  }
}

/**
 * Fetch RDAP data for a domain.
 */
async function fetchRDAP(domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${RDAP_BASE}${encodeURIComponent(domain)}`, {
      signal: controller.signal,
      headers: { Accept: 'application/rdap+json' },
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(timer);
    return null;
  }
}

/**
 * Get a lightweight fingerprint of a domain for comparison.
 * Queries: A records, NS records, SOA, registration date.
 */
async function getDomainFingerprint(domain) {
  const [aData, nsData, soaData, rdapData] = await Promise.all([
    queryDNS(domain, 'A'),
    queryDNS(domain, 'NS'),
    queryDNS(domain, 'SOA'),
    fetchRDAP(domain),
  ]);

  const aRecords = aData?.Answer?.filter(r => r.type === 1)?.map(r => r.data) ?? [];
  const nsRecords = nsData?.Answer?.filter(r => r.type === 2)?.map(r => r.data?.replace(/\.$/, '').toLowerCase()) ?? [];
  const soaRecord = soaData?.Answer?.find(r => r.type === 6);

  // Extract SOA fields
  let soaPrimary = '', soaAdmin = '';
  if (soaRecord?.data) {
    const soaParts = soaRecord.data.split(/\s+/);
    soaPrimary = soaParts[0]?.replace(/\.$/, '').toLowerCase() || '';
    soaAdmin = soaParts[1]?.replace(/\.$/, '').toLowerCase() || '';
  }

  // Extract RDAP info
  let registrantOrg = '', registrar = '', registrationDate = '';
  if (rdapData) {
    // Registrant
    const registrant = rdapData.entities?.find(e => e.roles?.includes('registrant'));
    if (registrant) {
      const vcard = registrant.vcardArray?.[1] ?? [];
      const orgEntry = vcard.find(item => item[0] === 'org');
      registrantOrg = orgEntry?.[3] || '';
      if (!registrantOrg) {
        const fnEntry = vcard.find(item => item[0] === 'fn');
        registrantOrg = fnEntry?.[3] || '';
      }
    }
    // Registrar
    const registrarEntity = rdapData.entities?.find(e => e.roles?.includes('registrar'));
    if (registrarEntity) {
      const vcard = registrarEntity.vcardArray?.[1] ?? [];
      const fnEntry = vcard.find(item => item[0] === 'fn');
      registrar = fnEntry?.[3] || registrarEntity.handle || '';
    }
    // Registration date
    const regEvent = rdapData.events?.find(e =>
      e.eventAction === 'registration' || e.eventAction === 'Registration'
    );
    registrationDate = regEvent?.eventDate || '';
  }

  // Domain age in days
  let ageDays = -1;
  if (registrationDate) {
    ageDays = Math.floor((Date.now() - new Date(registrationDate).getTime()) / (1000 * 60 * 60 * 24));
  }

  return {
    domain,
    ips: aRecords,
    nameservers: nsRecords,
    soaPrimary,
    soaAdmin,
    registrantOrg,
    registrar,
    registrationDate,
    ageDays,
    rdapAvailable: !!rdapData,
    resolved: aRecords.length > 0,
  };
}

/**
 * Compare two domain fingerprints and determine if current domain
 * is impersonating the canonical domain.
 *
 * Returns a comparison object with:
 *   - isImpersonation: boolean
 *   - confidence: 0-100 (how certain we are)
 *   - penalties: array of { reason, severity }
 *   - detail: human-readable explanation
 */
function compareFingerprints(current, canonical, brandName) {
  const penalties = [];
  let impersonationScore = 0; // higher = more likely impersonation

  // 1. Different IPs (strong indicator — real site resolves differently)
  if (current.ips.length > 0 && canonical.ips.length > 0) {
    const sharedIPs = current.ips.filter(ip => canonical.ips.includes(ip));
    if (sharedIPs.length === 0) {
      impersonationScore += 25;
      penalties.push({
        reason: `IPs don't match canonical "${canonical.domain}" (${canonical.ips[0]} vs ${current.ips[0]})`,
        severity: 'high',
      });
    }
  }

  // 2. Different nameservers
  if (current.nameservers.length > 0 && canonical.nameservers.length > 0) {
    const nsOverlap = current.nameservers.some(ns =>
      canonical.nameservers.some(cns => {
        // Compare NS provider (e.g., both use cloudflare)
        const nsDomain = getApexDomain(ns);
        const cnsDomain = getApexDomain(cns);
        return nsDomain === cnsDomain;
      })
    );
    if (!nsOverlap) {
      impersonationScore += 20;
      penalties.push({
        reason: `Nameservers differ from "${canonical.domain}" (${current.nameservers[0] || '?'} vs ${canonical.nameservers[0] || '?'})`,
        severity: 'high',
      });
    }
  }

  // 3. Different registrant organization
  if (current.registrantOrg && canonical.registrantOrg) {
    const normCurrent = current.registrantOrg.toLowerCase().replace(/[^a-z0-9]/g, '');
    const normCanonical = canonical.registrantOrg.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!normCurrent.includes(normCanonical) && !normCanonical.includes(normCurrent)) {
      impersonationScore += 25;
      penalties.push({
        reason: `Registrant mismatch: "${current.registrantOrg}" vs canonical "${canonical.registrantOrg}"`,
        severity: 'critical',
      });
    }
  } else if (canonical.registrantOrg && !current.registrantOrg) {
    impersonationScore += 10;
    penalties.push({
      reason: `Current site has no registrant info but canonical "${canonical.domain}" does ("${canonical.registrantOrg}")`,
      severity: 'medium',
    });
  }

  // 4. Different registrar
  if (current.registrar && canonical.registrar) {
    const normCurrReg = current.registrar.toLowerCase().replace(/[^a-z0-9]/g, '');
    const normCanReg = canonical.registrar.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!normCurrReg.includes(normCanReg) && !normCanReg.includes(normCurrReg)) {
      impersonationScore += 10;
      penalties.push({
        reason: `Different registrar from canonical domain`,
        severity: 'medium',
      });
    }
  }

  // 5. SOA mismatch
  if (current.soaPrimary && canonical.soaPrimary) {
    const currentSOAApex = getApexDomain(current.soaPrimary);
    const canonicalSOAApex = getApexDomain(canonical.soaPrimary);
    if (currentSOAApex !== canonicalSOAApex) {
      impersonationScore += 15;
      penalties.push({
        reason: `SOA primary nameserver differs (${current.soaPrimary} vs ${canonical.soaPrimary})`,
        severity: 'high',
      });
    }
  }

  // 6. Age comparison — real brands are OLD, spoofs are NEW
  if (canonical.ageDays > 365 && current.ageDays >= 0 && current.ageDays < 180) {
    impersonationScore += 20;
    penalties.push({
      reason: `Current domain is ${current.ageDays} days old, but canonical "${canonical.domain}" is ${Math.floor(canonical.ageDays / 365)} years old`,
      severity: 'critical',
    });
  }

  // 7. Current domain doesn't resolve but canonical does
  if (!current.resolved && canonical.resolved) {
    impersonationScore += 15;
    penalties.push({
      reason: `Current domain does not resolve, but canonical "${canonical.domain}" does`,
      severity: 'high',
    });
  }

  // Cap at 100
  const confidence = Math.min(impersonationScore, 100);
  const isImpersonation = confidence >= 30;

  let detail;
  if (confidence >= 70) {
    detail = `CRITICAL: This site is almost certainly impersonating "${brandName}" (${canonical.domain}). ${penalties.length} mismatch(es) detected with ${confidence}% confidence.`;
  } else if (confidence >= 50) {
    detail = `HIGH RISK: This site likely impersonates "${brandName}" (${canonical.domain}). ${penalties.length} difference(s) from the real domain.`;
  } else if (confidence >= 30) {
    detail = `WARNING: This site may be impersonating "${brandName}" (${canonical.domain}). ${penalties.length} discrepancy(ies) detected.`;
  } else {
    detail = `No strong impersonation signals detected for brand "${brandName}".`;
  }

  return {
    isImpersonation,
    confidence,
    penalties,
    detail,
    canonicalDomain: canonical.domain,
    brandName,
    currentFingerprint: current,
    canonicalFingerprint: canonical,
  };
}

/**
 * Detect which brand (if any) the current domain is trying to impersonate.
 * Returns the brand keyword and canonical domain, or null.
 */
function detectBrandInDomain(hostname) {
  const apex = getApexDomain(hostname);
  const parts = hostname.toLowerCase().split('.');
  const apexRoot = apex.split('.')[0];

  // Check each brand
  for (const [brand, canonical] of Object.entries(BRAND_CANONICAL)) {
    const canonicalApex = getApexDomain(canonical);

    // Skip if this IS the canonical domain
    if (apex === canonicalApex) return null;

    // Check if brand appears in any part of the hostname
    const found = parts.some(part => {
      if (part === brand) return true;
      // Fuzzy: check if part contains the brand (e.g., "paypal-login" contains "paypal")
      if (part.includes(brand) && part !== apex.split('.')[0]) return true;
      return false;
    });

    // Also check if the apex root itself is trying to look like the brand
    // (typosquatting case: "paypa1.com" trying to be "paypal.com")
    const isSimilar = isTyposquat(apexRoot, brand);

    if (found || isSimilar) {
      return { brand, canonical };
    }
  }

  return null;
}

/**
 * Simple typosquatting detection between two strings.
 */
function isTyposquat(input, brand) {
  if (input === brand) return false;
  if (input.length < 3 || brand.length < 3) return false;

  // Levenshtein distance ≤ 2
  const dist = levenshtein(input, brand);
  if (dist > 0 && dist <= 2 && input.length >= brand.length - 1) return true;

  // Character substitution (0→o, 1→l, etc.)
  const deconfused = input
    .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
    .replace(/4/g, 'a').replace(/5/g, 's').replace(/\$/g, 's')
    .replace(/@/g, 'a').replace(/!/g, 'i');
  if (deconfused === brand) return true;

  // Hyphen removal
  if (input.replace(/-/g, '') === brand) return true;

  return false;
}

/**
 * Levenshtein edit distance.
 */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

// ═══════════════════════════════════════════════════════════════════════
// AUTHORITATIVE DNS VERIFICATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Perform authoritative DNS verification:
 * 1. Query SOA to identify the primary authoritative nameserver
 * 2. Query NS to get all authoritative nameservers
 * 3. Verify consistency between SOA and NS records
 * 4. Check if authoritative servers are from known providers
 */
async function verifyAuthoritativeDNS(hostname) {
  const apex = getApexDomain(hostname);

  const [soaData, nsData] = await Promise.all([
    queryDNS(apex, 'SOA'),
    queryDNS(apex, 'NS'),
  ]);

  const soaRecord = soaData?.Answer?.find(r => r.type === 6);
  const nsRecords = nsData?.Answer?.filter(r => r.type === 2)?.map(r => r.data?.replace(/\.$/, '').toLowerCase()) ?? [];

  let soaPrimary = '', soaAdmin = '', soaSerial = '';
  if (soaRecord?.data) {
    const parts = soaRecord.data.split(/\s+/);
    soaPrimary = parts[0]?.replace(/\.$/, '').toLowerCase() || '';
    soaAdmin = parts[1]?.replace(/\.$/, '').toLowerCase() || '';
    soaSerial = parts[2] || '';
  }

  const issues = [];
  const verifications = [];

  // 1. SOA exists
  if (soaPrimary) {
    verifications.push(`SOA primary: ${soaPrimary}`);
  } else {
    issues.push('No SOA record — cannot identify authoritative DNS server');
  }

  // 2. NS records exist
  if (nsRecords.length > 0) {
    verifications.push(`${nsRecords.length} authoritative nameserver(s)`);
  } else {
    issues.push('No NS records — domain has no declared authoritative servers');
  }

  // 3. SOA primary should match one of the NS records
  if (soaPrimary && nsRecords.length > 0) {
    const soaInNS = nsRecords.some(ns => ns === soaPrimary || ns.endsWith(soaPrimary) || soaPrimary.endsWith(ns));
    if (soaInNS) {
      verifications.push('SOA ↔ NS consistency verified');
    } else {
      issues.push(`SOA primary (${soaPrimary}) not found among NS records — possible DNS misconfiguration`);
    }
  }

  // 4. Multiple nameservers (redundancy)
  if (nsRecords.length === 1) {
    issues.push('Only 1 nameserver — no DNS redundancy');
  } else if (nsRecords.length >= 2) {
    // Check if nameservers are in different domains (better resilience)
    const nsApexes = new Set(nsRecords.map(ns => getApexDomain(ns)));
    if (nsApexes.size >= 2) {
      verifications.push('Multiple NS providers (good redundancy)');
    }
  }

  // 5. Known provider identification
  const knownProviders = {
    'cloudflare': 'Cloudflare', 'awsdns': 'AWS Route53', 'google': 'Google Cloud DNS',
    'azure': 'Azure DNS', 'digitalocean': 'DigitalOcean', 'godaddy': 'GoDaddy',
    'namecheap': 'Namecheap', 'hostpapa': 'HostPapa', 'netlify': 'Netlify',
    'vercel': 'Vercel', 'squarespace': 'Squarespace', 'wix': 'Wix', 'shopify': 'Shopify',
  };

  let provider = '';
  for (const ns of nsRecords) {
    for (const [key, name] of Object.entries(knownProviders)) {
      if (ns.includes(key)) { provider = name; break; }
    }
    if (provider) break;
  }
  if (provider) verifications.push(`NS provider: ${provider}`);

  return {
    soaPrimary,
    soaAdmin,
    soaSerial,
    nameservers: nsRecords,
    provider,
    issues,
    verifications,
    status: issues.length === 0 ? 'pass' : (issues.length >= 2 ? 'warn' : 'pass'),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN EXPORT — Full Authoritative Lookup + Impersonation Check
// ═══════════════════════════════════════════════════════════════════════

/**
 * Main export — runs authoritative verification and impersonation detection.
 *
 * @param {string} hostname - current site's hostname
 * @returns {Promise<{ status, label, detail, raw }>}
 */
export async function checkAuthoritative(hostname) {
  const apex = getApexDomain(hostname);

  // Step 1: Authoritative DNS verification
  const authResult = await verifyAuthoritativeDNS(hostname);

  // Step 2: Brand impersonation detection
  const brandMatch = detectBrandInDomain(hostname);
  let impersonation = null;

  if (brandMatch) {
    // This domain contains a brand name — compare against the real one
    const [currentFP, canonicalFP] = await Promise.all([
      getDomainFingerprint(apex),
      getDomainFingerprint(brandMatch.canonical),
    ]);

    impersonation = compareFingerprints(currentFP, canonicalFP, brandMatch.brand);
  }

  // Step 3: Build result
  const issues = [...authResult.issues];
  const verifications = [...authResult.verifications];

  if (impersonation?.isImpersonation) {
    issues.push(impersonation.detail);
    for (const p of impersonation.penalties) {
      issues.push(`[${p.severity.toUpperCase()}] ${p.reason}`);
    }
  }

  let status, detail;

  if (impersonation?.isImpersonation && impersonation.confidence >= 50) {
    status = 'fail';
    detail = impersonation.detail + ' · ' + verifications.join(' · ');
  } else if (impersonation?.isImpersonation) {
    status = 'warn';
    detail = impersonation.detail + ' · ' + verifications.join(' · ');
  } else if (authResult.issues.length > 0) {
    status = 'warn';
    detail = `${verifications.join(' · ')}. ⚠ ${issues.join(' · ')}`;
  } else {
    status = 'pass';
    detail = verifications.join(' · ') + '. Authoritative DNS verified.';
  }

  return {
    status,
    label: 'Authoritative Verification',
    detail,
    raw: {
      soaPrimary: authResult.soaPrimary,
      soaAdmin: authResult.soaAdmin,
      nameservers: authResult.nameservers.join(', '),
      nsProvider: authResult.provider || 'Unknown',
      impersonation: impersonation ? {
        isImpersonation: impersonation.isImpersonation,
        confidence: impersonation.confidence,
        canonicalDomain: impersonation.canonicalDomain,
        brandName: impersonation.brandName,
        penalties: impersonation.penalties.length,
      } : 'None detected',
    },
  };
}
