/**
 * safeBrowsing.js
 * Checks a URL against the Google Safe Browsing API v4.
 *
 * Requires a user-supplied API key stored in chrome.storage.sync.
 * If no key is configured, returns status: 'skip' with guidance.
 *
 * Threat types checked:
 *   - MALWARE
 *   - SOCIAL_ENGINEERING  (phishing)
 *   - UNWANTED_SOFTWARE
 *   - POTENTIALLY_HARMFUL_APPLICATION
 *
 * API doc: https://developers.google.com/safe-browsing/v4/lookup-api
 */

const SB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const TIMEOUT_MS = 8000;

/**
 * Build the Safe Browsing API request body.
 * @param {string} url - full URL to check
 * @returns {Object} - JSON body for POST request
 */
function buildRequestBody(url) {
  return {
    client: {
      clientId: 'trustlens-extension',
      clientVersion: '1.0.0',
    },
    threatInfo: {
      // All major threat types
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  };
}

/**
 * Main module export — checks URL against Google Safe Browsing.
 * @param {string} url - full URL including protocol
 * @returns {Promise<{ status, label, detail, raw }>}
 */
export async function checkSafeBrowsing(url) {
  // ── Check for API key ─────────────────────────────────────────────────────
  // Key is stored by the user in the Options page via chrome.storage.sync
  let apiKey;
  try {
    const stored = await chrome.storage.sync.get('safeBrowsingKey');
    apiKey = stored.safeBrowsingKey;
  } catch {
    apiKey = null;
  }

  if (!apiKey || apiKey.trim() === '') {
    // No key — skip this module gracefully rather than silently failing
    return {
      status: 'skip',
      label: 'Safe Browsing',
      detail: 'API key not configured — open Settings to add your Google Safe Browsing API key.',
      raw: { skipped: true },
    };
  }

  // ── Perform API request ───────────────────────────────────────────────────
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const endpoint = `${SB_ENDPOINT}?key=${encodeURIComponent(apiKey.trim())}`;
    const res = await fetch(endpoint, {
      method: 'POST',
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildRequestBody(url)),
    });
    clearTimeout(timer);

    if (!res.ok) {
      // API error (e.g., invalid key, quota exceeded)
      const errText = await res.text().catch(() => res.status.toString());
      return {
        status: 'warn',
        label: 'Safe Browsing',
        detail: `API request failed (HTTP ${res.status}). Check your API key or quota.`,
        raw: { error: errText, status: res.status },
      };
    }

    const data = await res.json();

    // ── Interpret response ────────────────────────────────────────────────
    // An empty response body {} means the URL is clean (no matches found)
    if (!data.matches || data.matches.length === 0) {
      return {
        status: 'pass',
        label: 'Safe Browsing',
        detail: 'No threats detected by Google Safe Browsing.',
        raw: { matches: [] },
      };
    }

    // Threat(s) detected — extract details
    const threatTypes = [...new Set(data.matches.map(m => m.threatType))];
    const threatStr = threatTypes.join(', ').replace(/_/g, ' ').toLowerCase();

    return {
      status: 'fail',
      label: 'Safe Browsing',
      detail: `⚠ Threat detected: ${threatStr}. This URL is flagged in Google's threat database.`,
      raw: { matches: data.matches, threatTypes },
    };

  } catch (err) {
    clearTimeout(timer);
    const isTimeout = err.name === 'AbortError';
    return {
      status: 'warn',
      label: 'Safe Browsing',
      detail: isTimeout
        ? 'Safe Browsing check timed out — skipping.'
        : 'Safe Browsing check failed due to a network error.',
      raw: { error: err.message },
    };
  }
}
