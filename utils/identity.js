
const RDAP_BASE  = 'https://rdap.org/domain/';
const DOH_BASE   = 'https://dns.google/resolve';
const TIMEOUT_MS = 8000;

const KNOWN_PROVIDERS = {
  nameservers: {
    'cloudflare': 'Cloudflare', 'awsdns': 'Amazon Web Services',
    'google': 'Google Cloud', 'azure': 'Microsoft Azure',
    'digitalocean': 'DigitalOcean', 'godaddy': 'GoDaddy',
    'hostpapa': 'HostPapa', 'bluehost': 'Bluehost',
    'siteground': 'SiteGround', 'namecheap': 'Namecheap',
    'dreamhost': 'DreamHost', 'hostgator': 'HostGator',
    'ovh': 'OVH', 'hetzner': 'Hetzner', 'linode': 'Linode/Akamai',
    'vultr': 'Vultr', 'ns1': 'NS1', 'dnsimple': 'DNSimple',
    'route53': 'Amazon Route 53', 'netlify': 'Netlify',
    'vercel': 'Vercel', 'firebase': 'Firebase/Google',
    'squarespace': 'Squarespace', 'wix': 'Wix',
    'shopify': 'Shopify', 'wordpress': 'WordPress.com',
    'automattic': 'Automattic',
  },
  mx: {
    'google': 'Google Workspace', 'googlemail': 'Google Workspace',
    'outlook': 'Microsoft 365', 'protection.outlook': 'Microsoft 365',
    'mimecast': 'Mimecast', 'protonmail': 'ProtonMail',
    'zoho': 'Zoho Mail', 'pphosted': 'Proofpoint',
    'barracuda': 'Barracuda', 'messagelabs': 'Symantec/Broadcom',
    'mailgun': 'Mailgun', 'sendgrid': 'SendGrid/Twilio',
    'amazonses': 'Amazon SES', 'hostpapa': 'HostPapa',
  },
};

const GOV_TLD_PATTERNS = [
  /\.gov$/i, /\.mil$/i,
  /\.gov\.[a-z]{2}$/i, /\.gob\.[a-z]{2}$/i, /\.govt\.[a-z]{2}$/i,
  /\.go\.[a-z]{2}$/i, /\.nic\.in$/i, /\.gc\.ca$/i,
  /\.gouv\.fr$/i, /\.bund\.de$/i, /\.overheid\.nl$/i,
  /\.admin\.ch$/i, /\.gv\.at$/i, /\.europa\.eu$/i,
];

const EDU_TLD_PATTERNS = [
  /\.edu$/i, /\.edu\.[a-z]{2}$/i,
  /\.ac\.[a-z]{2}$/i, /\.university$/i,
];


async function fetchRDAP(hostname) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${RDAP_BASE}${encodeURIComponent(hostname)}`, {
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

// Queries DNS records using Google DoH
async function queryDNS(domain, type) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
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

function extractRegistrantInfo(rdapData) {
  const info = { org: '', name: '', country: '', email: '', registrar: '' };
  if (!rdapData || !rdapData.entities) return info;

  for (const entity of rdapData.entities) {
    const roles = entity.roles || [];

    if (roles.includes('registrant')) {
      const vcard = (entity.vcardArray && entity.vcardArray[1]) ? entity.vcardArray[1] : [];
      for (const item of vcard) {
        if (item[0] === 'org')   info.org     = item[3] || '';
        if (item[0] === 'fn')    info.name    = item[3] || '';
        if (item[0] === 'adr') {
          const adr = item[3];
          if (Array.isArray(adr)) info.country = adr[adr.length - 1] || '';
        }
        if (item[0] === 'email') info.email   = item[3] || '';
      }
    }

    if (roles.includes('registrar')) {
      const vcard = (entity.vcardArray && entity.vcardArray[1]) ? entity.vcardArray[1] : [];
      for (const item of vcard) {
        if (item[0] === 'fn') info.registrar = item[3] || '';
      }
      if (!info.registrar && entity.handle) info.registrar = entity.handle;
    }

    // Registrar may be nested inside another entity
    if (entity.entities) {
      for (const subEntity of entity.entities) {
        const subRoles = subEntity.roles || [];
        if (subRoles.includes('registrar') && !info.registrar) {
          const vcard = (subEntity.vcardArray && subEntity.vcardArray[1]) ? subEntity.vcardArray[1] : [];
          for (const item of vcard) {
            if (item[0] === 'fn') info.registrar = item[3] || '';
          }
        }
      }
    }
  }

  return info;
}

function extractDomainStatus(rdapData) {
  if (!rdapData || !rdapData.status) return [];
  return rdapData.status;
}

function identifyNSProvider(nameservers) {
  for (const ns of nameservers) {
    const lower = ns.toLowerCase();
    for (const [key, name] of Object.entries(KNOWN_PROVIDERS.nameservers)) {
      if (lower.includes(key)) return name;
    }
  }
  return '';
}

function identifyMXProvider(mxRecords) {
  for (const mx of mxRecords) {
    const lower = mx.toLowerCase();
    for (const [key, name] of Object.entries(KNOWN_PROVIDERS.mx)) {
      if (lower.includes(key)) return name;
    }
  }
  return '';
}

function isGovTLD(hostname) {
  return GOV_TLD_PATTERNS.some(function(pattern) { return pattern.test(hostname); });
}

function isEduTLD(hostname) {
  return EDU_TLD_PATTERNS.some(function(pattern) { return pattern.test(hostname); });
}

function getRegistrableDomain(hostname) {
  const parts     = hostname.split('.');
  const knownSLDs = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'go', 'gob', 'govt', 'nic', 'res']);
  if (parts.length >= 3 && knownSLDs.has(parts[parts.length - 2]) && parts[parts.length - 1].length <= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}


export async function checkIdentity(hostname, tabId, pageMeta) {
  const registrableDomain = getRegistrableDomain(hostname);

  const results = await Promise.all([
    fetchRDAP(registrableDomain),
    queryDNS(hostname, 'NS'),
    queryDNS(hostname, 'MX'),
    queryDNS(hostname, 'TXT'),
    queryDNS('_dmarc.' + hostname, 'TXT'),
  ]);

  const rdapData  = results[0];
  const nsData    = results[1];
  const mxData    = results[2];
  const txtData   = results[3];
  const dmarcData = results[4];

  const issues        = [];
  const verifications = [];
  const identityData  = {};

  const registrant   = extractRegistrantInfo(rdapData);
  const domainStatus = extractDomainStatus(rdapData);

  identityData.registrant    = registrant;
  identityData.domainStatus  = domainStatus;
  identityData.rdapAvailable = !!rdapData;

  if (rdapData) {
    if (registrant.org)       verifications.push('Registered to: ' + registrant.org);
    if (registrant.registrar) verifications.push('Registrar: ' + registrant.registrar);
    if (registrant.country)   verifications.push('Country: ' + registrant.country);

    const dangerousStatuses = ['serverHold', 'clientHold', 'pendingDelete', 'redemptionPeriod'];
    const goodStatuses      = ['clientDeleteProhibited', 'clientTransferProhibited', 'serverDeleteProhibited', 'serverTransferProhibited'];

    const dangerFlags = domainStatus.filter(function(s) { return dangerousStatuses.includes(s); });
    const goodFlags   = domainStatus.filter(function(s) { return goodStatuses.includes(s); });

    if (dangerFlags.length > 0) issues.push('Domain has concerning status: ' + dangerFlags.join(', '));
    if (goodFlags.length > 0)   verifications.push('Domain locked (' + goodFlags.length + ' protection(s))');
  } else {
    issues.push('RDAP registration data unavailable — cannot verify domain ownership');
  }

  var nsRecords = nsData?.Answer?.filter(r => r.type === 2).map(r => (r.data || '').replace(/\.$/, '')) ?? [];
  var mxRecords = mxData?.Answer?.filter(r => r.type === 15).map(r => r.data || '') ?? [];
  var txtRecords = txtData?.Answer?.filter(r => r.type === 16).map(r => (r.data || '').replace(/^"|"$/g, '')) ?? [];
  var dmarcTxtRecords = dmarcData?.Answer?.filter(r => r.type === 16).map(r => (r.data || '').replace(/^"|"$/g, '')) ?? [];

  var nsProvider = identifyNSProvider(nsRecords);
  if (nsProvider) { verifications.push('DNS: ' + nsProvider); identityData.nsProvider = nsProvider; }

  var mxProvider = identifyMXProvider(mxRecords);
  if (mxProvider) { verifications.push('Email: ' + mxProvider); identityData.mxProvider = mxProvider; }

  var spfRecord = txtRecords.find(r => r.toLowerCase().startsWith('v=spf1')) || null;

  if (spfRecord) {
    identityData.spf = spfRecord;
    if (spfRecord.indexOf('+all') !== -1) {
      issues.push('SPF allows ALL senders (+all) — extremely dangerous');
    } else if (spfRecord.indexOf('-all') !== -1) {
      verifications.push('SPF: strict policy (-all)');
    } else if (spfRecord.indexOf('~all') !== -1) {
      verifications.push('SPF: soft-fail (~all)');
    }
  } else {
    issues.push('No SPF record — email not authenticated');
  }

  var dmarcRecord = dmarcTxtRecords.find(r => r.toLowerCase().startsWith('v=dmarc1')) || null;

  if (dmarcRecord) {
    identityData.dmarc = dmarcRecord;
    var pMatch = dmarcRecord.match(/;\s*p\s*=\s*(\w+)/i);
    var policy = pMatch ? pMatch[1].toLowerCase() : 'none';
    if (policy === 'reject')         verifications.push('DMARC: reject (strongest protection)');
    else if (policy === 'quarantine') verifications.push('DMARC: quarantine');
    else if (policy === 'none')      issues.push('DMARC policy is "none" — monitoring only, no email spoofing protection');
  } else {
    issues.push('No DMARC record — domain not protected from email spoofing');
  }

  var isVerifiedGov = isGovTLD(hostname);
  var isVerifiedEdu = isEduTLD(hostname);
  var siteClaimsGov = (pageMeta && pageMeta.claimsGov) || false;

  identityData.isVerifiedGov = isVerifiedGov;
  identityData.isVerifiedEdu = isVerifiedEdu;

  if (isVerifiedGov) verifications.unshift('Verified Government Domain (official TLD)');
  if (isVerifiedEdu) verifications.unshift('Verified Educational Institution (official TLD)');

  // Site claiming .gov legitimacy without the TLD is near-certain fraud
  if (siteClaimsGov && !isVerifiedGov) {
    issues.push('CRITICAL: Site claims to be a government source but is NOT on a verified government TLD');
    return {
      status: 'fail',
      label:  'Identity & Ownership',
      detail: issues.join(' · '),
      raw: {
        registrant:          registrant.org || registrant.name || 'Redacted/Unknown',
        registrar:           registrant.registrar || 'Unknown',
        siteClaimsGov:       true,
        isVerifiedGov:       false,
        identityConsistency: 'fraud-suspected',
        verifications,
        issues,
      },
    };
  }

  // Consistency score: how many identity signals are present
  var consistencyScore = 0;
  var totalChecks      = 0;

  totalChecks++; if (registrant.org)       consistencyScore++;
  totalChecks++; if (registrant.registrar) consistencyScore++;
  totalChecks++; if (nsRecords.length > 0) consistencyScore++;
  totalChecks++; if (mxRecords.length > 0) consistencyScore++;
  totalChecks++; if (spfRecord)            consistencyScore++;
  totalChecks++; if (dmarcRecord)          consistencyScore++;
  totalChecks++; if (domainStatus.some(function(s) { return s.indexOf('Prohibited') !== -1; })) consistencyScore++;

  var consistencyPct = Math.round((consistencyScore / totalChecks) * 100);
  identityData.consistencyScore = consistencyPct;

  var status = 'pass';
  if (issues.some(function(i) { return i.indexOf('CRITICAL') !== -1 || i.indexOf('extremely dangerous') !== -1; })) {
    status = 'fail';
  } else if (issues.length >= 3 || consistencyPct < 30) {
    status = 'warn';
  } else if (issues.length > 0) {
    status = issues.length >= 2 ? 'warn' : 'pass';
  }

  if (isVerifiedGov || isVerifiedEdu) {
    if (status !== 'fail') status = 'pass';
  }

  var detailParts = [];
  if (verifications.length > 0) detailParts.push(verifications.join(' · '));
  if (issues.length > 0)        detailParts.push('Issues: ' + issues.join(' · '));
  detailParts.push('Identity consistency: ' + consistencyPct + '% (' + consistencyScore + '/' + totalChecks + ' checks)');
  var detail = detailParts.join(' · ');

  return {
    status,
    label: 'Identity & Ownership',
    detail,
    raw: {
      registrant:        registrant.org || registrant.name || 'Redacted/Unknown',
      registrar:         registrant.registrar || 'Unknown',
      country:           registrant.country || 'Unknown',
      nsProvider:        nsProvider || 'Unknown',
      mxProvider:        mxProvider || 'None',
      hasSPF:            !!spfRecord,
      hasDMARC:          !!dmarcRecord,
      domainStatus:      domainStatus.join(', ') || 'Unknown',
      isVerifiedGov,
      isVerifiedEdu,
      siteClaimsGov,
      consistencyScore:  consistencyPct,
      consistencyChecks: consistencyScore + '/' + totalChecks,
      verifications,
      issues,
    },
  };
}
