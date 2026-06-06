
const TIMEOUT_MS = 8000;


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

function extractRegistrationDate(data) {
  if (!data?.events) return null;

  const regEvent = data.events.find(
    e => e.eventAction === 'registration' || e.eventAction === 'Registration'
  );
  return regEvent?.eventDate ?? null;
}

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


export async function checkDomainAge(hostname) {
  const parts = hostname.split('.');
  const domain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  const primaryUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const fallbackUrl = `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`;

  let data = await fetchRDAP(primaryUrl);

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
    status = 'fail';
    detail = `Registered ${formattedDate} — only ${ageLabel}. Domains this new carry high phishing risk.`;
  } else if (days < 180) {
    status = 'warn';
    detail = `Registered ${formattedDate} (${ageLabel}). Recently registered domains are more likely to be malicious.`;
  } else {
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
