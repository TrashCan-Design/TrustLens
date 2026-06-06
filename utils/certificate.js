
const TRUSTED_CAS = {
  tier1: [
    'digicert', 'comodo', 'sectigo', 'globalsign', 'entrust',
    'geotrust', 'thawte', 'symantec', 'verisign', 'godaddy',
    'starfield', 'trustwave', 'cybertrust',
  ],
  tier2: [
    "let's encrypt", 'letsencrypt', 'r3', 'e1', 'r10', 'r11',
    'isrg root', 'internet security research group',
    'amazon', 'cloudflare', 'google trust services',
    'microsoft', 'apple', 'baltimore',
    'ssl.com', 'zerossl', 'buypass',
  ],
  tier3: [
    'actalis', 'certigna', 'camerfirma', 'secom',
    'e-tugra', 'turktrust', 'certum', 'certinomis',
    'quovadis', 'swisssign', 'atos', 'dhimyotis',
    'netlock', 'cnnic', 'cfca', 'wosign',
  ],
};


function classifyCA(issuerName) {
  if (!issuerName) return { trusted: false, tier: 0, name: 'Unknown' };
  const lower = issuerName.toLowerCase();

  for (const ca of TRUSTED_CAS.tier1) {
    if (lower.includes(ca)) return { trusted: true, tier: 1, name: ca };
  }
  for (const ca of TRUSTED_CAS.tier2) {
    if (lower.includes(ca)) return { trusted: true, tier: 2, name: ca };
  }
  for (const ca of TRUSTED_CAS.tier3) {
    if (lower.includes(ca)) return { trusted: true, tier: 3, name: ca };
  }

  return { trusted: false, tier: 0, name: issuerName };
}


function determineCertType(certDetails) {
  if (!certDetails) return 'Unknown';

  const subject = certDetails?.subject ?? '';
  const issuer = certDetails?.issuer ?? '';

  if (subject.includes('serialNumber=') || subject.includes('businessCategory=')) {
    return 'EV';
  }

  if (subject.includes('O=') || subject.includes('organizationName=')) {
    return 'OV';
  }

  return 'DV';
}


export async function checkSSL(tabId, hostname, securityInfo = null) {
  try {
    const tab = await chrome.tabs.get(tabId);
    const url = tab.url || '';
    const isHTTPS = url.startsWith('https://');
    const isHTTP  = url.startsWith('http://');

    if (!securityInfo) {
      if (!isHTTPS && !isHTTP) {
        return {
          status: 'warn',
          label: 'SSL Certificate',
          detail: 'Page is loaded via a non-HTTP/S protocol — full SSL check not applicable.',
          raw: { protocol: url.split(':')[0], source: 'url-check', certType: 'N/A' },
        };
      }

      if (isHTTP) {
        return {
          status: 'fail',
          label: 'SSL Certificate',
          detail: 'Site uses plain HTTP — no SSL/TLS encryption. All data is transmitted in clear text. Never enter credentials on this site.',
          raw: { protocol: 'http', encrypted: false, source: 'url-check', certType: 'None' },
        };
      }

      return {
        status: 'pass',
        label: 'SSL Certificate',
        detail: 'Connection encrypted via HTTPS. Certificate details could not be retrieved in this context, but the connection is secure.',
        raw: {
          protocol: 'https',
          encrypted: true,
          source: 'url-check',
          certType: 'Unknown (no detail available)',
          hostname,
        },
      };
    }

    const { state, details } = securityInfo;

    if (state === 'insecure' || state === 'broken') {
      return {
        status: 'fail',
        label: 'SSL Certificate',
        detail: `SSL security state is "${state}". The connection is not properly encrypted. Do not trust this site with sensitive data.`,
        raw: { ...securityInfo, certType: 'Invalid' },
      };
    }

    if (!details) {
      return {
        status: isHTTPS ? 'pass' : 'fail',
        label: 'SSL Certificate',
        detail: isHTTPS
          ? 'HTTPS confirmed. Certificate details unavailable in this context.'
          : 'No SSL detected.',
        raw: { state, source: 'security-state', certType: isHTTPS ? 'Unknown' : 'None' },
      };
    }

    const certDetails = details.certificate;
    const issues = [];
    const positives = [];

    const issuer = certDetails?.issuer ?? '';
    const subject = certDetails?.subject ?? '';
    const caInfo = classifyCA(issuer);
    const certType = determineCertType(certDetails);

    if (caInfo.trusted) {
      positives.push(`Issued by trusted CA: ${issuer} (Tier ${caInfo.tier})`);
    } else if (issuer && issuer !== subject) {
      issues.push(`Certificate issued by unrecognized CA: "${issuer}"`);
    }

    if (certType === 'EV') {
      positives.push('Extended Validation (EV) — highest trust level, organization identity verified');
    } else if (certType === 'OV') {
      positives.push('Organization Validated (OV) — business identity verified by CA');
    } else if (certType === 'DV') {
      positives.push('Domain Validated (DV) — domain ownership confirmed, but organization not verified');
    }

    const sanNames = certDetails?.subjectAlternativeNames ?? [];
    const certSubject = certDetails?.subject ?? '';
    const hostnameMatches = sanNames.some(san =>
      san.name === hostname ||
      (san.name.startsWith('*.') && hostname.endsWith(san.name.slice(1)))
    ) || certSubject.includes(hostname);

    if (!hostnameMatches && sanNames.length > 0) {
      issues.push('Certificate domain mismatch — cert is NOT issued for this hostname. This is a critical security issue.');
    }

    if (issuer && subject && issuer === subject) {
      issues.push('Self-signed certificate — not issued by a trusted CA. The site operator generated their own certificate.');
    }

    let expiryStr = 'Unknown';
    let daysUntilExpiry = Infinity;
    let validFrom = 'Unknown';
    let certAgeInDays = 0;

    if (certDetails?.validityPeriod?.end) {
      const expiry = new Date(certDetails.validityPeriod.end * 1000);
      expiryStr = expiry.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
      daysUntilExpiry = Math.floor((expiry - new Date()) / (1000 * 60 * 60 * 24));

      if (daysUntilExpiry < 0) {
        issues.push('Certificate has EXPIRED — the site is no longer securely verified');
      } else if (daysUntilExpiry < 7) {
        issues.push(`Certificate expires in ${daysUntilExpiry} day(s) — critical`);
      } else if (daysUntilExpiry < 30) {
        issues.push(`Certificate expires soon — ${daysUntilExpiry} day(s) remaining`);
      }
    }

    if (certDetails?.validityPeriod?.start) {
      const start = new Date(certDetails.validityPeriod.start * 1000);
      validFrom = start.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
      certAgeInDays = Math.floor((new Date() - start) / (1000 * 60 * 60 * 24));

      // Fresh cert can indicate a newly set-up fraudulent site
      if (certAgeInDays < 7) {
        issues.push('Certificate was issued very recently (< 7 days) — could indicate a newly compromised or fraudulent site');
      }
    }

    const wildcardSANs = sanNames.filter(san => san.name?.startsWith('*.'));
    if (wildcardSANs.length > 0) {
      positives.push(`Wildcard certificate covering ${wildcardSANs.map(s => s.name).join(', ')}`);
    }

    if (sanNames.length > 50) {
      issues.push(`Unusually high number of SANs (${sanNames.length}) — may indicate a shared/CDN certificate`);
    }

    if (issues.length > 0) {
      const isCritical = issues.some(i =>
        i.includes('Self-signed') || i.includes('mismatch') ||
        i.includes('EXPIRED') || i.includes('unrecognized CA')
      );
      return {
        status: isCritical ? 'fail' : 'warn',
        label: 'SSL Certificate',
        detail: issues.join(' · ') + (positives.length > 0 ? ` · ${positives.join(' · ')}` : ''),
        raw: {
          issuer, certType, caInfo,
          expiryStr, validFrom, daysUntilExpiry, certAgeInDays,
          issues, positives,
          sanCount: sanNames.length,
          sanNames: sanNames.slice(0, 10).map(s => s.name),
        },
      };
    }

    return {
      status: 'pass',
      label: 'SSL Certificate',
      detail: positives.join(' · ') + ` · Expires: ${expiryStr}.`,
      raw: {
        issuer, certType, caInfo,
        expiryStr, validFrom, daysUntilExpiry, certAgeInDays,
        issues: [], positives,
        sanCount: sanNames.length,
      },
    };

  } catch (err) {
    return {
      status: 'warn',
      label: 'SSL Certificate',
      detail: 'SSL check encountered an error — possibly restricted page (chrome://, about:).',
      raw: { error: err.message },
    };
  }
}



const BRAND_NAMES = new Set([
  'paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft',
  'netflix', 'instagram', 'twitter', 'linkedin', 'whatsapp', 'youtube',
  'gmail', 'outlook', 'office365', 'dropbox', 'icloud', 'tiktok',
  'snapchat', 'telegram', 'discord', 'slack', 'zoom', 'teams',
  'spotify', 'twitch', 'reddit', 'pinterest', 'tumblr',
  'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'barclays',
  'hsbc', 'sbi', 'hdfc', 'icici', 'paytm', 'phonepe', 'gpay',
  'jpmorgan', 'goldmansachs', 'morganstanley', 'deutschebank',
  'ubs', 'creditsuisse', 'santander', 'ing', 'bnpparibas',
  'standardchartered', 'rbs', 'natwest', 'lloyds', 'halifax',
  'nationwide', 'capitalone', 'discover', 'amex', 'americanexpress',
  'ebay', 'shopify', 'stripe', 'square', 'venmo', 'cashapp',
  'coinbase', 'binance', 'crypto', 'kraken', 'blockchain',
  'metamask', 'trustwallet', 'opensea',
  'walmart', 'target', 'bestbuy', 'costco', 'alibaba', 'aliexpress',
  'wish', 'etsy', 'wayfair',
  'irs', 'usps', 'fedex', 'ups', 'dhl',
  'norton', 'mcafee', 'kaspersky', 'avast', 'bitdefender',
  'lastpass', '1password', 'dashlane', 'okta', 'auth0',
]);

const KNOWN_SLDS = new Set([
  'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil',
  'or', 'ne', 'go', 'gob', 'nic', 'res', 'nhs', 'police', 'govt',
]);

// Checks for homograph / IDN characters
function hasNonASCII(str) {
  // eslint-disable-next-line no-control-regex
  return /[^\x00-\x7F]/.test(str);
}

function detectMixedScripts(str) {
  const scripts = new Set();
  for (const char of str) {
    const code = char.codePointAt(0);
    if (code >= 0x0041 && code <= 0x024F) scripts.add('Latin');
    else if (code >= 0x0400 && code <= 0x04FF) scripts.add('Cyrillic');
    else if (code >= 0x0370 && code <= 0x03FF) scripts.add('Greek');
    else if (code >= 0x0600 && code <= 0x06FF) scripts.add('Arabic');
    else if (code >= 0x4E00 && code <= 0x9FFF) scripts.add('CJK');
    else if (code >= 0x3040 && code <= 0x309F) scripts.add('Hiragana');
    else if (code >= 0x30A0 && code <= 0x30FF) scripts.add('Katakana');
    else if (code >= 0x0900 && code <= 0x097F) scripts.add('Devanagari');
  }
  return { mixed: scripts.size > 1, scripts: [...scripts] };
}

function getApexDomain(parts) {
  if (parts.length >= 3 &&
      KNOWN_SLDS.has(parts[parts.length - 2]) &&
      parts[parts.length - 1].length <= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function isIPAddress(hostname) {
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) return true;
  if (hostname.includes(':') && /^[0-9a-f:]+$/i.test(hostname)) return true;
  if (hostname.startsWith('[') && hostname.endsWith(']')) return true;
  return false;
}

function detectTyposquatting(domain) {
  const lower = domain.toLowerCase();


  const substitutions = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '@': 'a', '$': 's', '!': 'i',
  };


  for (const brand of BRAND_NAMES) {
    if (lower === brand) continue; // Exact match is fine


    if (brand.length > 3 && lower.length === brand.length - 1) {
      let mismatches = 0;
      let bi = 0;
      for (let i = 0; i < lower.length; i++) {
        if (lower[i] !== brand[bi]) {
          mismatches++;
          bi++; // skip one brand char
        }
        bi++;
      }
      if (mismatches <= 1 && bi >= brand.length - 1) {
        return { detected: true, brand, technique: 'character-omission' };
      }
    }


    if (lower.length === brand.length) {
      let diffs = 0;
      for (let i = 0; i < lower.length; i++) {
        if (lower[i] !== brand[i]) diffs++;
      }
      if (diffs === 1 || diffs === 2) {
        return { detected: true, brand, technique: 'character-swap' };
      }
    }


    if (lower.length === brand.length + 1) {
      const deduped = lower.replace(/(.)\1+/g, '$1');
      if (deduped === brand || deduped === brand.replace(/(.)\1+/g, '$1')) {
        return { detected: true, brand, technique: 'character-doubling' };
      }
    }


    if (lower.replace(/-/g, '') === brand) {
      return { detected: true, brand, technique: 'hyphenation' };
    }
  }

  return { detected: false, brand: '', technique: '' };
}

export async function checkDomainStructure(hostname) {
  const parts = hostname.toLowerCase().split('.');
  const issues = [];
  const flags = {};

  if (isIPAddress(hostname)) {
    return {
      status: 'warn',
      label: 'Domain Structure',
      detail: 'Site is accessed via IP address, not a domain name. This bypasses DNS and certificate verification. Exercise caution.',
      raw: { hostname, isIP: true, flags: { ipAddress: true } },
    };
  }

  const apex = getApexDomain(parts);
  const subdomainParts = parts.slice(0, parts.length - apex.split('.').length);
  const subdomainDepth = subdomainParts.length;
  const fullSubdomain = subdomainParts.join('.');

  if (hasNonASCII(hostname)) {
    issues.push('Non-ASCII characters detected — possible homograph/IDN spoofing attack');
    flags.homograph = true;


    const scriptAnalysis = detectMixedScripts(hostname);
    if (scriptAnalysis.mixed) {
      issues.push(`Mixed scripts detected: ${scriptAnalysis.scripts.join(' + ')} — strong phishing indicator`);
      flags.mixedScripts = true;
    }
  }

  if (hostname.includes('xn--')) {
    issues.push('Punycode (internationalized) domain detected — verify the actual displayed characters');
    flags.punycode = true;
  }

  if (subdomainDepth > 3) {
    issues.push(`Unusually deep subdomain nesting (${subdomainDepth} levels) — typical of URL padding attacks`);
    flags.deepNesting = true;
  } else if (subdomainDepth > 2) {

    flags.moderateNesting = true;
  }

  const embeddedBrands = subdomainParts.filter(part => BRAND_NAMES.has(part));
  if (embeddedBrands.length > 0) {
    const apexRoot = apex.split('.')[0];
    const falseBrands = embeddedBrands.filter(b => b !== apexRoot);
    if (falseBrands.length > 0) {
      issues.push(`Brand name "${falseBrands[0]}" used as subdomain of unrelated apex "${apex}" — LIKELY PHISHING`);
      flags.brandSpoofing = true;
    }
  }

  const apexRoot = apex.split('.')[0];
  const typosquat = detectTyposquatting(apexRoot);
  if (typosquat.detected) {
    issues.push(`Domain "${apexRoot}" resembles "${typosquat.brand}" (${typosquat.technique}) — possible typosquatting`);
    flags.typosquatting = true;
  }

  const suspiciousPatterns = [
    { pattern: /^(secure|login|signin|verify|account|update|confirm|validation|auth)$/, label: 'auth-keyword' },
    { pattern: /^(bank|payment|billing|invoice|wallet|money|transfer)$/, label: 'financial-keyword' },
    { pattern: /^(admin|webmail|cpanel|portal|dashboard|console)$/, label: 'admin-keyword' },
  ];

  for (const sub of subdomainParts) {
    for (const { pattern, label } of suspiciousPatterns) {
      if (pattern.test(sub)) {

        flags[`suspiciousSub_${label}`] = sub;
      }
    }
  }

  const hyphenCount = hostname.split('-').length - 1;
  if (hyphenCount > 3) {
    issues.push(`Excessive use of hyphens (${hyphenCount}) — common in phishing domains`);
    flags.hyphenAbuse = true;
  }

  if (hostname.length > 60) {
    issues.push(`Unusually long hostname (${hostname.length} chars) — may be used to hide the true domain`);
    flags.longHostname = true;
  }

  const numericSubs = subdomainParts.filter(p => /^\d+$/.test(p));
  if (numericSubs.length > 0 && subdomainDepth > 1) {
    flags.numericSubdomains = true;
  }

  let status, detail;

  if (flags.homograph || flags.brandSpoofing || flags.mixedScripts) {
    status = 'fail';
    detail = issues.join(' · ');
  } else if (flags.typosquatting || flags.deepNesting || flags.hyphenAbuse) {
    status = 'warn';
    detail = issues.join(' · ');
  } else if (issues.length > 0) {
    status = 'warn';
    detail = issues.join(' · ');
  } else {
    status = 'pass';
    const extras = [];
    if (subdomainDepth > 0) extras.push(`subdomain depth: ${subdomainDepth}`);
    if (subdomainDepth === 0) extras.push('no subdomains');
    detail = `Domain structure looks normal. Apex: "${apex}"${extras.length ? ', ' + extras.join(', ') : ''}.`;
  }

  return {
    status,
    label: 'Domain Structure',
    detail,
    raw: {
      hostname,
      apex,
      subdomains: subdomainParts,
      subdomainDepth,
      fullSubdomain,
      hostnameLength: hostname.length,
      flags,
    },
  };
}
