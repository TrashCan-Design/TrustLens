const WEIGHTS = {
  authoritative: 20,
  identity:      18,
  ssl:           12,
  dns:           14,
  sb:            14,
  age:            8,
  domain:         6,
  tld:            8,
};


export function computeScore(results) {
  let earned   = 0;
  let possible = 0;
  const breakdown = [];

  // Cross-module escalations: combine weak signals into stronger verdicts
  if (results.tld?.status === 'fail') {
    if (results.age?.status === 'fail' || results.age?.status === 'warn') {
      if (results.domain?.status === 'pass') {
        results.domain = {
          ...results.domain,
          status: 'warn',
          detail: `Domain structure looks normal but TLD is high-risk with a young/unverified domain. ${results.domain.detail}`,
        };
      }
    }
    if (results.identity?.status === 'warn') {
      results.identity = {
        ...results.identity,
        status: 'fail',
        detail: `High-risk TLD combined with weak identity verification. ${results.identity.detail}`,
      };
    }
  }

  if (results.domain?.status === 'warn' && results.tld?.status === 'fail') {
    results.domain = {
      ...results.domain,
      status: 'fail',
      detail: `Suspicious domain structure on high-risk TLD. ${results.domain.detail}`,
    };
  }

  if (results.ssl?.status === 'fail' && results.identity?.status === 'fail') {
    results.identity = {
      ...results.identity,
      detail: `CRITICAL: No SSL + identity failure. ${results.identity.detail}`,
    };
  }

  if (results.dns?.status === 'fail' && results.identity?.status === 'warn') {
    results.identity = {
      ...results.identity,
      status: 'fail',
      detail: `DNS resolution failed with weak identity. ${results.identity.detail}`,
    };
  }

  if (results.authoritative?.status === 'fail' && results.domain?.status === 'warn') {
    results.domain = {
      ...results.domain,
      status: 'fail',
      detail: `Impersonation suspected + suspicious domain. ${results.domain.detail}`,
    };
  }

  // DV certs are trivially obtainable — downgrade to warn when impersonation is likely
  if (results.authoritative?.status === 'fail' && results.ssl?.status === 'pass') {
    const certType = results.ssl?.raw?.certType;
    if (certType === 'DV' || certType === 'Unknown' || certType === 'Unknown (no detail available)') {
      results.ssl = {
        ...results.ssl,
        status: 'warn',
        detail: `SSL present but only ${certType || 'DV'} — impersonation sites can get DV certs easily. ${results.ssl.detail}`,
      };
    }
  }

  if (results.tld?.status === 'fail' && results.ssl?.status === 'pass') {
    const certType = results.ssl?.raw?.certType;
    if (!certType || certType === 'DV' || certType === 'Unknown' || certType === 'Unknown (no detail available)') {
      results.ssl = {
        ...results.ssl,
        status: 'warn',
        detail: `SSL/HTTPS present but only basic DV certificate on a high-risk TLD — DV certs are free and prove nothing about legitimacy. ${results.ssl.detail}`,
      };
    }
  }

  if (results.dns?.status === 'warn' && results.tld?.status === 'fail') {
    results.dns = {
      ...results.dns,
      status: 'fail',
      detail: `Incomplete DNS/email infrastructure on a high-risk TLD. ${results.dns.detail}`,
    };
  }

  let warnCount = 0;
  let failCount = 0;
  let skipCount = 0;

  for (const [key] of Object.entries(WEIGHTS)) {
    const status = results[key]?.status ?? 'skip';
    if (status === 'warn')      warnCount++;
    else if (status === 'fail') failCount++;
    else if (status === 'skip') skipCount++;
  }

  for (const [key, weight] of Object.entries(WEIGHTS)) {
    const result = results[key];
    const status = result?.status ?? 'skip';

    let points = 0;
    if (status === 'pass') {
      points = weight;
    } else if (status === 'warn') {
      points = weight * 0.35;
    } else if (status === 'fail') {
      points = 0;
    } else {
      // skipped modules contribute a small partial credit
      points = weight * 0.2;
    }

    earned   += points;
    possible += weight;

    breakdown.push({
      key,
      weight,
      status,
      points: Math.round(points * 10) / 10,
      label:  result?.label ?? key,
      detail: result?.detail ?? '',
    });
  }

  let score = possible > 0 ? Math.round((earned / possible) * 100) : 0;

  // Accumulative penalties for multiple weak/failed modules
  if (warnCount > 1) score -= (warnCount - 1) * 4;
  if (failCount > 1) score -= (failCount - 1) * 6;
  if (warnCount >= 2 && failCount >= 1) score -= 8;
  if (skipCount >= 2) score -= skipCount * 3;

  if (results.tld?.status === 'fail') {
    score = Math.min(score, 45); // risky TLD can't land in "Trusted" or "Moderate"
  }

  if (results.darkweb?.status === 'fail') score = Math.min(score, 10);
  if (results.sb?.status === 'fail')      score = Math.min(score, 15);

  // Site claiming to be gov but not on a .gov TLD is near-certain fraud
  if (results.identity?.raw?.siteClaimsGov && !results.identity?.raw?.isVerifiedGov) {
    score = Math.min(score, 15);
  }

  let impersonationDetected = false;
  const impersonationData   = results.authoritative?.raw?.impersonation;

  if (impersonationData && typeof impersonationData === 'object' && impersonationData.isImpersonation) {
    impersonationDetected = true;
    const confidence = impersonationData.confidence || 0;

    if (confidence >= 70)      score = Math.min(score, 10);
    else if (confidence >= 50) score = Math.min(score, 20);
    else if (confidence >= 30) score = Math.min(score, 35);
  }

  score = Math.max(0, Math.min(100, score));

  let band, color;
  if (score >= 80) {
    band = 'Trusted';    color = '#00e5ff';
  } else if (score >= 60) {
    band = 'Moderate';   color = '#4dd0e1';
  } else if (score >= 40) {
    band = 'Caution';    color = '#ffb300';
  } else if (score >= 20) {
    band = 'Risky';      color = '#ff7043';
  } else {
    band = 'Dangerous';  color = '#ff3b3b';
  }

  return { score, band, color, breakdown, impersonationDetected };
}
