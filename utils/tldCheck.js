
const HIGH_RISK_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq',
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
  '.cam', '.zip', '.mov',
  '.cricket', '.science', '.review', '.party',
  '.trade', '.faith', '.accountant', '.date',
  '.men', '.webcam',
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

const TRUSTED_TLDS = new Set([
  '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
  '.dev', '.app', '.page', '.new',
  '.bank', '.insurance', '.health', '.hospital',
  '.law', '.abogado', '.cpa',
  '.gov', '.mil',
  '.museum', '.aero', '.coop', '.post',

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

  '.io', '.ai', '.tech', '.cloud', '.digital',
  '.info', '.pro', '.biz',
  '.eu',
  '.asia',

  '.google', '.apple', '.amazon', '.microsoft', '.youtube',
]);

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

// Common SLDs used in ccTLD patterns like .co.uk
const KNOWN_SLDS = new Set([
  'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil',
  'or', 'ne', 'go', 'gob', 'nic', 'res', 'nhs', 'police',
  'govt', 'gen', 'biz', 'info',
]);


function extractTLD(hostname) {
  const host  = hostname.replace(/\.$/, '').toLowerCase();
  const parts = host.split('.');

  if (parts.length < 2) return `.${host}`;

  if (parts.length >= 3) {
    const threePartSuffix = `.${parts.slice(-3).join('.')}`;
    if (TRUSTED_TLDS.has(threePartSuffix)) return threePartSuffix;
  }

  const twoPartSuffix = `.${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (TRUSTED_TLDS.has(twoPartSuffix) || HIGH_RISK_TLDS.has(twoPartSuffix) || MODERATE_RISK_TLDS.has(twoPartSuffix)) {
    return twoPartSuffix;
  }

  // Detect pattern like .co.uk where SLD is short and recognised
  if (KNOWN_SLDS.has(parts[parts.length - 2]) && parts[parts.length - 1].length <= 3) {
    return twoPartSuffix;
  }

  return `.${parts[parts.length - 1]}`;
}


export async function checkTLD(hostname) {
  const tld = extractTLD(hostname);

  let status, detail, riskLevel;

  if (HIGH_RISK_TLDS.has(tld)) {
    status    = 'fail';
    riskLevel = 'high';
    detail    = `The TLD "${tld}" is associated with free/low-cost domains widely abused for phishing and malware. High risk.`;
  } else if (TRUSTED_TLDS.has(tld)) {
    status    = 'pass';
    riskLevel = 'low';
    detail    = `"${tld}" is a well-established TLD with strong registrar oversight and low abuse rates.`;
  } else if (MODERATE_RISK_TLDS.has(tld)) {
    status    = 'warn';
    riskLevel = 'moderate';
    detail    = `"${tld}" has moderate risk — it's a legitimate TLD but sometimes used in suspicious domains. Exercise caution.`;
  } else {
    status    = 'warn';
    riskLevel = 'unknown';
    detail    = `"${tld}" is not in our database. Unlisted TLDs carry unknown risk — exercise caution.`;
  }

  return {
    status,
    label: 'TLD Risk',
    detail,
    raw: { tld, hostname, riskLevel },
  };
}
