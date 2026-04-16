/**
 * background.js — TrustLens Service Worker
 *
 * Responsibilities:
 *   1. Live connectivity check (fetch with 4s timeout + redirect detection)
 *   2. Cache management (chrome.storage.session, 5-min TTL)
 *   3. Badge text + color update after scan
 *   4. Message routing — popup sends SCAN request, background runs checks
 *   5. AUTO full scan on every page load → always shows popup with results
 *   6. ALL modules always run — no partial/fast mode
 *   7. Authoritative DNS + impersonation detection
 *
 * MV3 rules obeyed:
 *   - No persistent listeners (activates on demand)
 *   - No setInterval / long-lived processes
 *   - All async operations use Promise.allSettled()
 */

import { checkDNS }            from './utils/dns.js';
import { checkSSL, checkDomainStructure } from './utils/certificate.js';
import { checkTLD }            from './utils/tldCheck.js';
import { checkDomainAge }      from './utils/domainAge.js';
import { checkSafeBrowsing }   from './utils/safeBrowsing.js';
import { computeScore }        from './utils/scoreEngine.js';
import { checkIdentity }       from './utils/identity.js';
import { checkAuthoritative }  from './utils/authoritativeLookup.js';

// ── Cache constants ──────────────────────────────────────────────────────────
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/** Build the cache key for a domain */
function cacheKey(domain) {
  return `cache_${domain}`;
}

/**
 * Read a cached scan result from chrome.storage.session.
 */
async function readCache(domain) {
  try {
    const data = await chrome.storage.session.get(cacheKey(domain));
    const entry = data[cacheKey(domain)];
    if (!entry) return null;

    const age = Date.now() - entry.timestamp;
    if (age > CACHE_TTL_MS) {
      await chrome.storage.session.remove(cacheKey(domain));
      return null;
    }
    return entry.results;
  } catch {
    return null;
  }
}

/**
 * Write scan results to chrome.storage.session with a timestamp.
 */
async function writeCache(domain, results) {
  try {
    await chrome.storage.session.set({
      [cacheKey(domain)]: { results, timestamp: Date.now() },
    });
  } catch {}
}

// ── Dark Web Detection ──────────────────────────────────────────────────────

function checkDarkWeb(hostname) {
  const host = hostname.toLowerCase();
  if (host.endsWith('.onion')) {
    return {
      status: 'fail',
      label: 'Dark Web Detection',
      detail: 'WARNING: This is a .onion hidden service (Dark Web). Proceed with extreme caution.',
      raw: { type: 'onion' }
    };
  }
  if (host.endsWith('.i2p')) {
    return {
      status: 'fail',
      label: 'Dark Web Detection',
      detail: 'WARNING: This is an .i2p hidden service (I2P Darknet). Proceed with extreme caution.',
      raw: { type: 'i2p' }
    };
  }
  return null;
}

// ── Live Connectivity Check ──────────────────────────────────────────────────

async function checkLiveConnectivity(url, originalDomain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      method: 'HEAD',
      redirect: 'follow',
      cache: 'no-store',
      credentials: 'omit',
    });
    clearTimeout(timer);

    const finalUrl = res.url;
    let finalHostname = '';
    try {
      finalHostname = new URL(finalUrl).hostname;
    } catch {
      finalHostname = originalDomain;
    }

    const wasRedirected = finalHostname !== originalDomain;

    if (wasRedirected) {
      return {
        status: 'warn',
        label: 'Live Check',
        detail: `Site redirects to "${finalHostname}". Original: "${originalDomain}".`,
        raw: { originalDomain, finalHostname, statusCode: res.status },
      };
    }

    return {
      status: 'pass',
      label: 'Live Check',
      detail: `Site is reachable (HTTP ${res.status}).`,
      raw: { originalDomain, finalHostname, statusCode: res.status },
    };
  } catch (err) {
    clearTimeout(timer);
    const isTimeout = err.name === 'AbortError';
    return {
      status: 'fail',
      label: 'Live Check',
      detail: isTimeout ? 'Site did not respond within 4s.' : `Site unreachable: ${err.message}`,
      raw: { error: err.message, timeout: isTimeout },
    };
  }
}

// ── Badge Update ─────────────────────────────────────────────────────────────

async function updateBadge(score, color, tabId) {
  try {
    await chrome.action.setBadgeText({ text: score.toString(), tabId });
    await chrome.action.setBadgeBackgroundColor({ color, tabId });
  } catch {}
}

// ── Main Scan Orchestrator ───────────────────────────────────────────────────
// ALWAYS runs full scan — no fast/partial mode

async function runScan({ url, hostname, tabId, pageMeta }) {
  // ── Dark Web Check ──────────────────────────────────────────────────────
  const dwCheck = checkDarkWeb(hostname);
  
  // ── ALL modules run in parallel ─────────────────────────────────────────
  const allPromises = {
    tld:           checkTLD(hostname),
    domain:        checkDomainStructure(hostname),
    age:           checkDomainAge(hostname),
    live:          checkLiveConnectivity(url, hostname),
    dns:           checkDNS(hostname),
    ssl:           checkSSL(tabId, hostname, null),
    sb:            checkSafeBrowsing(url),
    identity:      checkIdentity(hostname, tabId, pageMeta),
    authoritative: checkAuthoritative(hostname),
  };

  const keys = Object.keys(allPromises);
  const settled = await Promise.allSettled(Object.values(allPromises));

  const results = {};
  keys.forEach((key, i) => {
    const outcome = settled[i];
    results[key] = outcome.status === 'fulfilled' ? outcome.value : {
      status: 'warn',
      label: key,
      detail: `Module error: ${outcome.reason?.message ?? 'Unknown'}`,
      raw: { error: outcome.reason?.message },
    };
  });

  if (dwCheck) results.darkweb = dwCheck;

  // CMS/WP Warning
  if (pageMeta?.isWordPress && !pageMeta?.hasContact) {
    results.cms = {
      status: 'warn',
      label: 'CMS Info',
      detail: 'WordPress site detected with no obvious contact information. Exercise caution.',
      raw: pageMeta
    };
  }

  return results;
}

// ── Auto-Run full scan on every page load ────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url?.startsWith('http')) {
    const url = tab.url;
    const hostname = new URL(url).hostname;

    (async () => {
      // Check cache first
      const cached = await readCache(hostname);
      if (cached) {
        await updateBadge(cached._score.score, cached._score.color, tabId);
        chrome.tabs.sendMessage(tabId, {
          type: 'SCAN_RESULTS',
          results: cached,
          score: cached._score,
          hostname,
          fromCache: true,
        }).catch(() => {});
        return;
      }

      // Notify content script that scan is starting
      chrome.tabs.sendMessage(tabId, {
        type: 'SCAN_STARTED',
        hostname,
      }).catch(() => {});

      const results = await runScan({ url, hostname, tabId });
      const scoreResult = computeScore(results);
      results._score = scoreResult;
      
      await writeCache(hostname, results);
      await updateBadge(scoreResult.score, scoreResult.color, tabId);

      // Send results to content script for auto-popup display
      chrome.tabs.sendMessage(tabId, {
        type: 'SCAN_RESULTS',
        results,
        score: scoreResult,
        hostname,
        fromCache: false,
      }).catch(() => {});

      // Also show risk alert banner for dangerous sites
      if (scoreResult.score < 50) {
        chrome.tabs.sendMessage(tabId, {
          type: 'RISK_ALERT',
          score: scoreResult.score,
          band: scoreResult.band
        }).catch(() => {});
      }
    })();
  }
});

// ── Message Listener ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'SCAN') {
    const { url, hostname, tabId, forceRefresh, pageMeta } = msg;

    (async () => {
      if (!forceRefresh) {
        const cached = await readCache(hostname);
        if (cached) {
          sendResponse({ success: true, results: cached, fromCache: true });
          return;
        }
      }

      let results;
      try {
        results = await runScan({ url, hostname, tabId, pageMeta });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
        return;
      }

      const scoreResult = computeScore(results);
      results._score = scoreResult;

      await writeCache(hostname, results);
      await updateBadge(scoreResult.score, scoreResult.color, tabId);
      sendResponse({ success: true, results, fromCache: false });
    })();
    return true;
  }

  if (msg.type === 'CLEAR_CACHE') {
    chrome.storage.session.clear().then(() => sendResponse({ success: true }));
    return true;
  }

  if (msg.type === 'PAGE_HOSTNAME') {
    return false;
  }
});
