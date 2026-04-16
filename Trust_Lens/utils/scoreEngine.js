/**
 * scoreEngine.js
 * Aggregates all module results into a single Trust Score (0–100).
 *
 * Module weights (total = 100):
 *   Authoritative Verification → 20  (SOA, NS, impersonation detection)
 *   Identity & Ownership       → 18  (RDAP, cross-source verification)
 *   SSL Certificate            → 12  (encryption + CA trust)
 *   DNS & Email Security       → 14  (SPF, DMARC, MX, NS, DNSSEC)
 *   Safe Browsing              → 14  (Google threat database)
 *   Domain Age                 → 8   (registration freshness)
 *   Domain Structure           → 6   (subdomain, homograph, typosquat)
 *   TLD Risk                   → 8   (TLD abuse classification)
 *
 * Scoring:
 *   pass → full weight
 *   warn → 35% weight (stricter than before)
 *   fail → 0
 *   skip → excluded but counts as weak signal (slight penalty)
 *
 * Compounding penalty:
 *   Multiple warns/fails interact — 3+ warnings add extra penalty
 *   TLD fail acts as a trust ceiling
 *
 * Overrides:
 *   Impersonation → hard cap based on confidence
 *   Dark web, Safe Browsing, Gov spoofing → hard caps
 */

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

/**
 * Compute a score from an object of module results.
 * @param {Object} results - keyed by module id, each with { status, label, detail, raw }
 * @returns {{ score: number, band: string, color: string, breakdown: Array, impersonationDetected: boolean }}
 */
export function computeScore(results) {
  let earned = 0;
  let possible = 0;
  const breakdown = [];

  // ── Correlation Logic (mutate results before scoring) ──────────────

  // 1. TLD fail + Age warn/fail → domain structure also becomes warn at minimum
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
    // TLD fail + identity warn → identity becomes fail
    if (results.identity?.status === 'warn') {
      results.identity = {
        ...results.identity,
        status: 'fail',
        detail: `High-risk TLD combined with weak identity verification. ${results.identity.detail}`,
      };
    }
  }

  // 2. Domain structure warn + TLD fail → domain structure becomes fail
  if (results.domain?.status === 'warn' && results.tld?.status === 'fail') {
    results.domain = {
      ...results.domain,
      status: 'fail',
      detail: `Suspicious domain structure on high-risk TLD. ${results.domain.detail}`,
    };
  }

  // 3. SSL fail + Identity fail = amplified danger
  if (results.ssl?.status === 'fail' && results.identity?.status === 'fail') {
    results.identity = {
      ...results.identity,
      detail: `CRITICAL: No SSL + identity failure. ${results.identity.detail}`,
    };
  }

  // 4. DNS fail + weak identity → identity worsens
  if (results.dns?.status === 'fail' && results.identity?.status === 'warn') {
    results.identity = {
      ...results.identity,
      status: 'fail',
      detail: `DNS resolution failed with weak identity. ${results.identity.detail}`,
    };
  }

  // 5. Authoritative fail + domain warn → domain becomes fail
  if (results.authoritative?.status === 'fail' && results.domain?.status === 'warn') {
    results.domain = {
      ...results.domain,
      status: 'fail',
      detail: `Impersonation suspected + suspicious domain. ${results.domain.detail}`,
    };
  }

  // 6. DV cert on impersonation site → downgrade SSL
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

  // 7. If TLD fails and SSL is only DV, downgrade SSL to warn
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

  // 8. DNS warn + TLD fail → DNS becomes fail
  if (results.dns?.status === 'warn' && results.tld?.status === 'fail') {
    results.dns = {
      ...results.dns,
      status: 'fail',
      detail: `Incomplete DNS/email infrastructure on a high-risk TLD. ${results.dns.detail}`,
    };
  }

  // ── Count warnings and failures ────────────────────────────────────
  let warnCount = 0;
  let failCount = 0;
  let skipCount = 0;

  for (const [key] of Object.entries(WEIGHTS)) {
    const status = results[key]?.status ?? 'skip';
    if (status === 'warn') warnCount++;
    else if (status === 'fail') failCount++;
    else if (status === 'skip') skipCount++;
  }

  // ── Score Calculation ──────────────────────────────────────────────
  for (const [key, weight] of Object.entries(WEIGHTS)) {
    const result = results[key];
    const status = result?.status ?? 'skip';

    let points = 0;
    if (status === 'pass') {
      points = weight;
    } else if (status === 'warn') {
      // Warns get only 35% of weight (stricter)
      points = weight * 0.35;
    } else if (status === 'fail') {
      points = 0;
    } else {
      // Skip — counts as 20% (slight negative bias for missing data)
      points = weight * 0.2;
    }

    earned += points;
    possible += weight;

    breakdown.push({
      key,
      weight,
      status,
      points: Math.round(points * 10) / 10,
      label: result?.label ?? key,
      detail: result?.detail ?? '',
    });
  }

  let score = possible > 0 ? Math.round((earned / possible) * 100) : 0;

  // ── Compounding Penalty ────────────────────────────────────────────
  // Multiple warnings/failures should compound — a site with 3 warns
  // and 1 fail is MUCH worse than one with just 1 warn.

  // Each warn after the 1st reduces score by 4 points
  if (warnCount > 1) {
    score -= (warnCount - 1) * 4;
  }

  // Each fail after the 1st reduces score by 6 points
  if (failCount > 1) {
    score -= (failCount - 1) * 6;
  }

  // Combined warn + fail penalty
  if (warnCount >= 2 && failCount >= 1) {
    score -= 8; // Extra penalty for mix of warns and fails
  }

  // Skipped modules are suspicious — reduce score slightly
  if (skipCount >= 2) {
    score -= skipCount * 3;
  }

  // ── TLD-based ceiling ──────────────────────────────────────────────
  // If TLD is high-risk (fail), cap the maximum possible score
  if (results.tld?.status === 'fail') {
    score = Math.min(score, 45); // Can't be above "Caution" with a risky TLD
  }

  // ── Override Checks ────────────────────────────────────────────────

  // Dark web → immediate 10
  if (results.darkweb?.status === 'fail') {
    score = Math.min(score, 10);
  }

  // Safe Browsing threat → cap at 15
  if (results.sb?.status === 'fail') {
    score = Math.min(score, 15);
  }

  // Government spoofing → cap at 15
  if (results.identity?.raw?.siteClaimsGov && !results.identity?.raw?.isVerifiedGov) {
    score = Math.min(score, 15);
  }

  // ── IMPERSONATION PENALTY ──────────────────────────────────────────
  let impersonationDetected = false;
  const impersonationData = results.authoritative?.raw?.impersonation;

  if (impersonationData && typeof impersonationData === 'object' && impersonationData.isImpersonation) {
    impersonationDetected = true;
    const confidence = impersonationData.confidence || 0;

    if (confidence >= 70) {
      score = Math.min(score, 10);
    } else if (confidence >= 50) {
      score = Math.min(score, 20);
    } else if (confidence >= 30) {
      score = Math.min(score, 35);
    }
  }

  // ── Floor at 0 ─────────────────────────────────────────────────────
  score = Math.max(0, Math.min(100, score));

  // ── Band Classification ────────────────────────────────────────────
  let band, color;
  if (score >= 80) {
    band = 'Trusted';
    color = '#00e5ff';
  } else if (score >= 60) {
    band = 'Moderate';
    color = '#4dd0e1';
  } else if (score >= 40) {
    band = 'Caution';
    color = '#ffb300';
  } else if (score >= 20) {
    band = 'Risky';
    color = '#ff7043';
  } else {
    band = 'Dangerous';
    color = '#ff3b3b';
  }

  return { score, band, color, breakdown, impersonationDetected };
}
