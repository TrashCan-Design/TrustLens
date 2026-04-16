/**
 * domainAge.js
 * Retrieves domain registration date via RDAP (Registration Data Access Protocol).
 *
 * Primary:  https://rdap.org/domain/DOMAIN
 * Fallback: https://rdap.verisign.com/com/v1/domain/DOMAIN  (for .com domains)
 *
 * Age bands:
 *   < 30 days   → fail  (very fresh — high phishing correlation)
 *   30–180 days → warn  (recently registered — caution)
 *   > 180 days  → pass  (established domain)
 */

const TIMEOUT_MS = 8000;

/**
 * Fetch RDAP data from a given URL.
 * @param {string} url
 * @returns {Promise<Object|null>}
 */
async function fetchRDAP(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(timer);
    return null;
  }
}

/**
 * Extract the registration date from an RDAP response object.
 * RDAP stores events in an array; we look for "registration" event.
 * @param {Object} data - raw RDAP JSON
 * @returns {string|null} ISO date string or null
 */
function extractRegistrationDate(data) {
  if (!data?.events) return null;

  // RDAP events have an eventAction and eventDate field
  const regEvent = data.events.find(
    e => e.eventAction === 'registration' || e.eventAction === 'Registration'
  );
  return regEvent?.eventDate ?? null;
}

/**
 * Calculate human-readable age from a date string.
 * @param {string} dateStr - ISO date string
 * @returns {{ days: number, label: string }}
 */
function calculateAge(dateStr) {
  const then = new Date(dateStr);
  const now = new Date();
  const diffMs = now - then;
  const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  let label;
  if (days < 30) {
    label = `${days} day${days !== 1 ? 's' : ''} old`;
  } else if (days < 365) {
    const months = Math.floor(days / 30);
    label = `~${months} month${months !== 1 ? 's' : ''} old`;
  } else {
    const years = Math.floor(days / 365);
    const remMonths = Math.floor((days % 365) / 30);
    label = `${years} yr${years !== 1 ? 's' : ''}${remMonths > 0 ? ` ${remMonths} mo` : ''} old`;
  }

  return { days, label };
}

/**
 * Main module export — checks domain age via RDAP.
 * @param {string} hostname - bare hostname
 * @returns {Promise<{ status, label, detail, raw }>}
 */
export async function checkDomainAge(hostname) {
  // Strip subdomains to get registrable domain
  // e.g. sub.example.co.uk → example.co.uk (simplified: take last 2 parts)
  const parts = hostname.split('.');
  const domain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  // Try primary RDAP source first, then Verisign fallback in parallel
  const primaryUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const fallbackUrl = `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`;

  // Try primary first
  let data = await fetchRDAP(primaryUrl);

  // If primary failed or returned no events, attempt fallback (Verisign .com only)
  if (!data || !data.events) {
    data = await fetchRDAP(fallbackUrl);
  }

  const registrationDate = extractRegistrationDate(data);

  if (!registrationDate) {
    return {
      status: 'warn',
      label: 'Domain Age',
      detail: 'Could not determine registration date — RDAP data unavailable for this domain.',
      raw: { domain, rdapAvailable: false },
    };
  }

  const { days, label: ageLabel } = calculateAge(registrationDate);
  const formattedDate = new Date(registrationDate).toLocaleDateString('en-GB', {
    day: 'numeric', month: 'long', year: 'numeric',
  });

  let status, detail;

  if (days < 30) {
    // Extremely fresh — very high risk for phishing
    status = 'fail';
    detail = `Registered ${formattedDate} — only ${ageLabel}. Domains this new carry high phishing risk.`;
  } else if (days < 180) {
    // Recently registered — caution warranted
    status = 'warn';
    detail = `Registered ${formattedDate} (${ageLabel}). Recently registered domains are more likely to be malicious.`;
  } else {
    // Established domain
    status = 'pass';
    detail = `Registered ${formattedDate} (${ageLabel}). Established domain with reasonable history.`;
  }

  return {
    status,
    label: 'Domain Age',
    detail,
    raw: { domain, registrationDate, days },
  };
}
