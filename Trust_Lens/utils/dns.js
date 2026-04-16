/**
 * dns.js
 * DNS lookup via Google's DNS-over-HTTPS (DoH) API.
 *
 * Checks:
 *   1. A records    — if none exist, domain doesn't resolve → fail
 *   2. MX records   — missing MX on a "business" site is suspicious → warn
 *   3. SPF records  — Sender Policy Framework (TXT record with "v=spf1")
 *   4. DMARC records — Domain-based Message Authentication (TXT at _dmarc.DOMAIN)
 *   5. NS records   — Nameserver verification
 *   6. AAAA records — IPv6 support
 *   7. CAA records  — Certificate Authority Authorization
 *
 * Endpoint: https://dns.google/resolve?name=DOMAIN&type=TYPE
 */

const DOH_BASE = 'https://dns.google/resolve';
const TIMEOUT_MS = 6000;

/**
 * Query Google DoH for a specific record type.
 * Returns the API JSON response, or null on failure.
 * @param {string} domain
 * @param {string} type - e.g. "A", "MX", "TXT", "NS"
 * @returns {Promise<Object|null>}
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
 * Parse SPF record from TXT records.
 * SPF records begin with "v=spf1".
 * @param {Array} txtRecords - array of TXT record data strings
 * @returns {{ found: boolean, record: string, mechanisms: string[], policy: string }}
 */
function parseSPF(txtRecords) {
  const spfRecord = txtRecords.find(r => r.toLowerCase().startsWith('v=spf1'));
  if (!spfRecord) return { found: false, record: '', mechanisms: [], policy: 'none' };

  const parts = spfRecord.split(/\s+/);
  const mechanisms = parts.filter(p => p !== 'v=spf1');

  // Determine the SPF policy (all, ~all, -all, ?all)
  let policy = 'neutral';
  const allMech = mechanisms.find(m => m.endsWith('all'));
  if (allMech) {
    if (allMech === '-all') policy = 'hard-fail';     // Strict: reject unauthorized senders
    else if (allMech === '~all') policy = 'soft-fail'; // Mark as suspicious
    else if (allMech === '+all') policy = 'pass-all';  // Dangerous: allows anyone
    else if (allMech === '?all') policy = 'neutral';
  }

  return { found: true, record: spfRecord, mechanisms, policy };
}

/**
 * Parse DMARC record from TXT records at _dmarc.domain.
 * DMARC records begin with "v=DMARC1".
 * @param {Array} txtRecords
 * @returns {{ found: boolean, record: string, policy: string, subPolicy: string, rua: string, ruf: string, pct: number }}
 */
function parseDMARC(txtRecords) {
  const dmarcRecord = txtRecords.find(r => r.toLowerCase().startsWith('v=dmarc1'));
  if (!dmarcRecord) return { found: false, record: '', policy: 'none', subPolicy: 'none', rua: '', ruf: '', pct: 100 };

  const tags = {};
  dmarcRecord.split(';').forEach(part => {
    const [key, ...vals] = part.trim().split('=');
    if (key) tags[key.trim().toLowerCase()] = vals.join('=').trim();
  });

  return {
    found: true,
    record: dmarcRecord,
    policy: tags.p || 'none',           // none, quarantine, reject
    subPolicy: tags.sp || tags.p || 'none',
    rua: tags.rua || '',                // Aggregate report URI
    ruf: tags.ruf || '',                // Forensic report URI
    pct: parseInt(tags.pct) || 100,     // Percentage of messages subject to filtering
  };
}

/**
 * Main module export — runs comprehensive DNS checks.
 * @param {string} hostname - bare hostname (no protocol)
 * @returns {Promise<{ status, label, detail, raw }>}
 */
export async function checkDNS(hostname) {
  // Run ALL DNS queries in parallel for speed
  const [aData, mxData, nsData, txtData, dmarcData, aaaaData, caaData] = await Promise.all([
    queryDNS(hostname, 'A'),
    queryDNS(hostname, 'MX'),
    queryDNS(hostname, 'NS'),
    queryDNS(hostname, 'TXT'),
    queryDNS(`_dmarc.${hostname}`, 'TXT'),
    queryDNS(hostname, 'AAAA'),
    queryDNS(hostname, 'CAA'),
  ]);

  // ── A Record analysis ─────────────────────────────────────────────────────
  const aRecords = aData?.Answer?.filter(r => r.type === 1) ?? [];
  const resolvedIPs = aRecords.map(r => r.data);

  // ── AAAA Record analysis ──────────────────────────────────────────────────
  const aaaaRecords = aaaaData?.Answer?.filter(r => r.type === 28) ?? [];
  const resolvedIPv6 = aaaaRecords.map(r => r.data);

  // ── NS Record analysis ────────────────────────────────────────────────────
  const nsRecords = nsData?.Answer?.filter(r => r.type === 2) ?? [];
  const nameservers = nsRecords.map(r => r.data?.replace(/\.$/, ''));

  // ── MX Record analysis ────────────────────────────────────────────────────
  const mxRecords = mxData?.Answer?.filter(r => r.type === 15) ?? [];
  const hasMX = mxRecords.length > 0;
  const mxHosts = mxRecords.map(r => r.data);

  // ── TXT / SPF analysis ────────────────────────────────────────────────────
  const txtRecords = txtData?.Answer?.filter(r => r.type === 16)?.map(r => r.data?.replace(/^"|"$/g, '')) ?? [];
  const spf = parseSPF(txtRecords);

  // ── DMARC analysis ────────────────────────────────────────────────────────
  const dmarcTxtRecords = dmarcData?.Answer?.filter(r => r.type === 16)?.map(r => r.data?.replace(/^"|"$/g, '')) ?? [];
  const dmarc = parseDMARC(dmarcTxtRecords);

  // ── CAA Record analysis ───────────────────────────────────────────────────
  const caaRecords = caaData?.Answer?.filter(r => r.type === 257) ?? [];
  const caaEntries = caaRecords.map(r => r.data);

  // ── DNSSEC Check ──────────────────────────────────────────────────────────
  // The AD (Authenticated Data) flag in the response header indicates DNSSEC validation
  const dnssecValidated = aData?.AD === true;

  // ── Determine status ──────────────────────────────────────────────────────
  const issues = [];
  const passes = [];

  // A Records
  if (resolvedIPs.length === 0) {
    issues.push('No A records — domain does not resolve');
  } else {
    passes.push(`Resolves to ${resolvedIPs[0]}${resolvedIPs.length > 1 ? ` (+${resolvedIPs.length - 1} more)` : ''}`);
  }

  // MX Records
  if (hasMX) {
    passes.push(`MX: ${mxHosts.length} mail server(s)`);
  } else {
    issues.push('No MX records — no mail infrastructure');
  }

  // SPF
  if (spf.found) {
    if (spf.policy === 'pass-all') {
      issues.push('SPF allows ALL senders (+all) — dangerous configuration');
    } else if (spf.policy === 'hard-fail') {
      passes.push('SPF: strict (-all)');
    } else if (spf.policy === 'soft-fail') {
      passes.push('SPF: soft-fail (~all)');
    } else {
      passes.push('SPF: present');
    }
  } else {
    issues.push('No SPF record — email sender not authenticated');
  }

  // DMARC
  if (dmarc.found) {
    if (dmarc.policy === 'reject') {
      passes.push('DMARC: reject policy (strongest)');
    } else if (dmarc.policy === 'quarantine') {
      passes.push('DMARC: quarantine policy');
    } else if (dmarc.policy === 'none') {
      issues.push('DMARC policy is "none" — monitoring only, no enforcement');
    } else {
      passes.push('DMARC: present');
    }
  } else {
    issues.push('No DMARC record — email domain not protected against spoofing');
  }

  // NS Records
  if (nameservers.length > 0) {
    passes.push(`NS: ${nameservers.length} nameserver(s)`);
  }

  // DNSSEC
  if (dnssecValidated) {
    passes.push('DNSSEC validated');
  }

  // CAA
  if (caaEntries.length > 0) {
    passes.push(`CAA: ${caaEntries.length} rule(s) — restricts which CAs can issue certificates`);
  }

  // ── Build final status ────────────────────────────────────────────────────
  let status, detail;

  if (resolvedIPs.length === 0) {
    status = 'fail';
    detail = 'DNS returned no A records — the domain does not resolve to any IP address.';
  } else if (issues.length > 2) {
    // Multiple email security issues
    status = 'warn';
    detail = `${passes.join(' · ')}. Issues: ${issues.join(' · ')}`;
  } else {
    status = 'pass';
    const allInfo = [...passes];
    if (issues.length > 0) allInfo.push(`⚠ ${issues.join(', ')}`);
    detail = allInfo.join(' · ');
  }

  return {
    status,
    label: 'DNS & Email Security',
    detail,
    raw: {
      aRecords: resolvedIPs,
      aaaaRecords: resolvedIPv6,
      mxRecords: mxHosts,
      nameservers,
      spf: spf.found ? { policy: spf.policy, record: spf.record } : { found: false },
      dmarc: dmarc.found ? { policy: dmarc.policy, rua: dmarc.rua, pct: dmarc.pct } : { found: false },
      caa: caaEntries,
      dnssecValidated,
      aQueryStatus: aData?.Status,
      mxQueryStatus: mxData?.Status,
    },
  };
}
