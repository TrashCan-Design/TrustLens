/**
 * tldCheck.js
 * Comprehensive TLD classification engine.
 *
 * Classifies the Top-Level Domain of a given hostname as:
 *   fail  → known high-risk / free-abuse TLDs
 *   pass  → established trusted TLDs
 *   warn  → unrecognised / unlisted TLD
 *
 * Covers:
 *   - Legacy gTLDs (.com, .org, .net, etc.)
 *   - Country-code TLDs (ccTLDs) with proper two-part handling
 *   - New gTLDs by risk tier
 *   - Google-operated HSTS-required TLDs
 *   - Highly regulated industry TLDs
 *   - Known high-abuse free-registration TLDs
 *   - Multi-part TLD extraction (.co.uk, .com.au, etc.)
 *
 * No network calls required — purely local data.
 */

// ── HIGH-RISK TLDs ──────────────────────────────────────────────────────────
// TLDs frequently abused for phishing, malware, spam, scams, and piracy
const HIGH_RISK_TLDS = new Set([
  // Freenom (formerly free) — massively abused
  '.tk', '.ml', '.ga', '.cf', '.gq',
  // Top spam/phishing TLDs (per Spamhaus, SURBL, abuse.ch data)
  '.xyz', '.top', '.click', '.loan', '.club',
  '.work', '.download', '.stream', '.racing',
  '.gdn', '.win', '.buzz', '.rest', '.bid',
  '.fun', '.icu', '.monster', '.sbs',
  '.pw',  '.bar', '.vip',
  '.life', '.live', '.online', '.site', '.website',
  '.space', '.host', '.press', '.world',
  '.link', '.surf', '.cyou', '.cfd',
  '.quest', '.bond', '.skin', '.hair',
  '.makeup', '.beauty', '.boats', '.homes',
  '.yachts', '.autos', '.motorcycles',
  '.cam', '.zip', '.mov',  // New Google TLDs often abused for phishing
  '.cricket', '.science', '.review', '.party',
  '.trade', '.faith', '.accountant', '.date',
  '.men', '.webcam',
  // Piracy / content theft TLDs
  '.rip', '.fit', '.lol', '.wtf', '.wang',
  '.ink', '.ren', '.kim', '.xin', '.ltd',
  '.guru', '.ninja', '.rocks', '.center', '.today',
  '.run', '.uno', '.lat', '.pics', '.vet',
  '.mobi', '.tel', '.tube', '.fans', '.exposed',
  '.gives', '.cheap', '.casa', '.best', '.coupons',
  '.deals', '.fail', '.gratis', '.limited', '.promo',
  '.review', '.tips', '.wiki', '.zone', '.market',
  '.support', '.help', '.limo', '.ooo',
]);

// ── TRUSTED TLDs ────────────────────────────────────────────────────────────
// Established TLDs with strong registrar oversight, regulatory requirements,
// or historically low abuse rates
const TRUSTED_TLDS = new Set([
  // Legacy gTLDs
  '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',

  // Google-operated (require HSTS preloading)
  '.dev', '.app', '.page', '.new',

  // Highly regulated / restricted
  '.bank', '.insurance', '.health', '.hospital',
  '.law', '.abogado', '.cpa',
  '.gov', '.mil',
  '.museum', '.aero', '.coop', '.post',

  // Major country-code TLDs (direct)
  '.us', '.uk', '.ca', '.au', '.de', '.fr', '.it', '.es',
  '.nl', '.be', '.ch', '.at', '.se', '.no', '.dk', '.fi',
  '.jp', '.kr', '.cn', '.tw', '.hk', '.sg', '.nz',
  '.br', '.mx', '.ar', '.cl', '.co', '.pe',
  '.in', '.za', '.eg', '.ng', '.ke', '.gh',
  '.ie', '.pt', '.pl', '.cz', '.sk', '.hu', '.ro', '.bg',
  '.hr', '.si', '.lt', '.lv', '.ee', '.lu',
  '.is', '.gr', '.cy', '.mt', '.ua', '.by',
  '.il', '.ae', '.sa', '.qa', '.kw', '.bh', '.om',
  '.th', '.my', '.ph', '.vn', '.id',
  '.ru', '.tr',

  // Two-part country-code TLDs
  '.co.uk', '.org.uk', '.ac.uk', '.gov.uk', '.nhs.uk', '.police.uk',
  '.co.in', '.org.in', '.net.in', '.gov.in', '.ac.in', '.res.in', '.nic.in',
  '.com.au', '.org.au', '.net.au', '.gov.au', '.edu.au',
  '.co.nz', '.org.nz', '.net.nz', '.govt.nz',
  '.co.za', '.org.za', '.gov.za', '.ac.za',
  '.co.jp', '.or.jp', '.ne.jp', '.ac.jp', '.go.jp',
  '.co.kr', '.or.kr', '.ne.kr', '.go.kr', '.ac.kr',
  '.com.br', '.org.br', '.net.br', '.gov.br', '.edu.br',
  '.com.mx', '.org.mx', '.gob.mx', '.edu.mx',
  '.com.ar', '.org.ar', '.gob.ar', '.edu.ar',
  '.com.cn', '.org.cn', '.net.cn', '.gov.cn', '.edu.cn',
  '.com.tw', '.org.tw', '.net.tw', '.gov.tw', '.edu.tw',
  '.com.sg', '.org.sg', '.net.sg', '.gov.sg', '.edu.sg',
  '.com.my', '.org.my', '.net.my', '.gov.my', '.edu.my',
  '.co.th', '.or.th', '.ac.th', '.go.th',
  '.com.ph', '.org.ph', '.net.ph', '.gov.ph', '.edu.ph',
  '.co.id', '.or.id', '.go.id', '.ac.id',
  '.com.tr', '.org.tr', '.net.tr', '.gov.tr', '.edu.tr',
  '.com.eg', '.org.eg', '.gov.eg', '.edu.eg',
  '.co.ke', '.or.ke', '.go.ke', '.ac.ke',
  '.com.ng', '.org.ng', '.gov.ng', '.edu.ng',
  '.com.gh', '.org.gh', '.gov.gh', '.edu.gh',
  '.co.il', '.org.il', '.net.il', '.gov.il', '.ac.il',
  '.com.sa', '.org.sa', '.net.sa', '.gov.sa', '.edu.sa',
  '.ae', '.com.ae', '.org.ae', '.gov.ae',
  '.com.qa', '.org.qa', '.gov.qa', '.edu.qa',
  '.com.de', '.org.de',
  '.co.fr', '.com.fr',

  // Established new gTLDs with good reputation
  '.io', '.ai', '.tech', '.cloud', '.digital',
  '.info', '.pro', '.biz',
  '.eu',
  '.asia',

  // Brand TLDs (restricted to their owners)
  '.google', '.apple', '.amazon', '.microsoft', '.youtube',
]);

// ── MODERATE RISK TLDs ──────────────────────────────────────────────────────
// Not high-risk, but not strongly trusted — exercise some caution
const MODERATE_RISK_TLDS = new Set([
  '.me', '.tv', '.ws', '.la',
  '.to', '.fm', '.am', '.ly',
  '.sh', '.sx', '.gg', '.gl',
  '.nu', '.cc',
  '.name', '.jobs',
  '.travel', '.xxx', '.adult', '.porn', '.sex',
  '.store', '.shop',
  '.agency', '.solutions', '.services',
  '.consulting', '.network', '.systems',
  '.media', '.studio', '.design',
  '.one',
]);

// ── Known Second-Level Domains ──────────────────────────────────────────────
// Used for multi-part TLD extraction
const KNOWN_SLDS = new Set([
  'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil',
  'or', 'ne', 'go', 'gob', 'nic', 'res', 'nhs', 'police',
  'govt', 'gen', 'biz', 'info',
]);

/**
 * Extract the effective TLD from a hostname.
 * Handles multi-part TLDs like .co.uk, .com.au, .gov.in correctly.
 * @param {string} hostname
 * @returns {string} TLD with leading dot, e.g. ".com" or ".co.uk"
 */
function extractTLD(hostname) {
  // Remove trailing dot if present (FQDN)
  const host = hostname.replace(/\.$/, '').toLowerCase();
  const parts = host.split('.');

  if (parts.length < 2) return `.${host}`;

  // Check for three-part TLD first (e.g. .pvt.k12.ma.us — unlikely but safe)
  if (parts.length >= 3) {
    const threePartSuffix = `.${parts.slice(-3).join('.')}`;
    if (TRUSTED_TLDS.has(threePartSuffix)) return threePartSuffix;
  }

  // Check for known two-part TLDs (e.g. co.uk, com.au, gov.in)
  const twoPartSuffix = `.${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (TRUSTED_TLDS.has(twoPartSuffix) || HIGH_RISK_TLDS.has(twoPartSuffix) || MODERATE_RISK_TLDS.has(twoPartSuffix)) {
    return twoPartSuffix;
  }

  // Check if second-to-last part is a known SLD with a short country code
  if (KNOWN_SLDS.has(parts[parts.length - 2]) && parts[parts.length - 1].length <= 3) {
    return twoPartSuffix;
  }

  return `.${parts[parts.length - 1]}`;
}

/**
 * Main module export — runs TLD risk classification.
 * @param {string} hostname - e.g. "sub.example.co.uk"
 * @returns {Promise<{ status, label, detail, raw }>}
 */
export async function checkTLD(hostname) {
  const tld = extractTLD(hostname);

  let status, detail, riskLevel;

  if (HIGH_RISK_TLDS.has(tld)) {
    status = 'fail';
    riskLevel = 'high';
    detail = `The TLD "${tld}" is associated with free/low-cost domains widely abused for phishing and malware. High risk.`;
  } else if (TRUSTED_TLDS.has(tld)) {
    status = 'pass';
    riskLevel = 'low';
    detail = `"${tld}" is a well-established TLD with strong registrar oversight and low abuse rates.`;
  } else if (MODERATE_RISK_TLDS.has(tld)) {
    status = 'warn';
    riskLevel = 'moderate';
    detail = `"${tld}" has moderate risk — it's a legitimate TLD but sometimes used in suspicious domains. Exercise caution.`;
  } else {
    // Unlisted — treat as caution, not fail
    status = 'warn';
    riskLevel = 'unknown';
    detail = `"${tld}" is not in our database. Unlisted TLDs carry unknown risk — exercise caution.`;
  }

  return {
    status,
    label: 'TLD Risk',
    detail,
    raw: { tld, hostname, riskLevel },
  };
}
