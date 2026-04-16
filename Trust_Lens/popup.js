/**
 * popup.js — TrustLens Popup Controller
 *
 * Responsibilities:
 *   - Detect current tab URL / hostname
 *   - Trigger FULL SCAN via background service worker (always full, no fast mode)
 *   - Render animated SVG ring gauge with trust score
 *   - Render staggered collapsible module cards
 *   - Clipboard export of plain-text report
 *   - First-run onboarding overlay
 *   - Impersonation alert display
 */

// ════════════════════════════════════════════════════════════════════
// DOM REFERENCES
// ════════════════════════════════════════════════════════════════════

const $  = id => document.getElementById(id);

const domainText    = $('current-domain');
const scoreNumber   = $('score-number');
const scoreBand     = $('score-band');
const ringFill      = $('ring-fill');
const ringPulse     = $('ring-pulse');
const rescanBtn     = $('rescan-btn');
const copyBtn       = $('copy-report-btn');
const cardsSection  = $('cards-section');
const onboardingEl  = $('onboarding-overlay');

// Module card ids in display order
const MODULE_IDS = ['authoritative', 'identity', 'ssl', 'dns', 'live', 'domain', 'tld', 'age', 'sb', 'cms', 'darkweb'];

// Ring circumference: 2π × r = 2π × 50 ≈ 314.16
const RING_CIRCUMFERENCE = 314;

// ════════════════════════════════════════════════════════════════════
// STATE
// ════════════════════════════════════════════════════════════════════

let currentResults  = null;
let currentHostname = null;
let currentUrl      = null;
let currentTabId    = null;

// ════════════════════════════════════════════════════════════════════
// ONBOARDING
// ════════════════════════════════════════════════════════════════════

async function checkOnboarding() {
  const { hasSeenOnboarding } = await chrome.storage.sync.get('hasSeenOnboarding');
  if (!hasSeenOnboarding) {
    onboardingEl.classList.remove('hidden');
    setupOnboarding();
  }
}

function setupOnboarding() {
  let currentStep = 1;
  const steps = document.querySelectorAll('.onboarding-step');
  const dots   = document.querySelectorAll('.ob-dot');
  const nextBtn = $('ob-next');
  const skipBtn = $('ob-skip');

  function goTo(step) {
    steps.forEach(s => s.classList.remove('active'));
    dots.forEach(d  => d.classList.remove('active'));
    document.querySelector(`.onboarding-step[data-step="${step}"]`).classList.add('active');
    document.querySelector(`.ob-dot[data-dot="${step}"]`).classList.add('active');
    currentStep = step;
    nextBtn.textContent = step === 3 ? 'Get Started' : 'Next';
  }

  nextBtn.addEventListener('click', () => {
    if (currentStep < 3) {
      goTo(currentStep + 1);
    } else {
      dismissOnboarding();
    }
  });

  skipBtn.addEventListener('click', dismissOnboarding);
}

function dismissOnboarding() {
  onboardingEl.classList.add('fade-out');
  setTimeout(() => onboardingEl.classList.add('hidden'), 350);
  chrome.storage.sync.set({ hasSeenOnboarding: true });
}

// ════════════════════════════════════════════════════════════════════
// RING GAUGE ANIMATION
// ════════════════════════════════════════════════════════════════════

/** Animate the SVG ring to fill to the given score (0–100) */
function animateRing(score, color) {
  const offset = RING_CIRCUMFERENCE - (score / 100) * RING_CIRCUMFERENCE;

  // Stop pulse animation
  ringPulse.classList.remove('pulsing');

  // Set colour
  ringFill.style.stroke = color;

  // Animate offset with CSS transition
  requestAnimationFrame(() => {
    ringFill.style.strokeDashoffset = offset.toString();
  });
}

/** Enter scanning state — show pulse, reset score */
function setScanning() {
  ringFill.style.strokeDashoffset = RING_CIRCUMFERENCE.toString();
  ringFill.style.stroke = '#00e5ff';
  ringPulse.classList.add('pulsing');
  scoreNumber.textContent = '—';
  scoreBand.textContent   = 'Scanning…';
  scoreNumber.style.color = '#00e5ff';
  scoreBand.style.color   = '';
}

/** Display final score in ring */
function displayScore(score, band, color) {
  scoreNumber.textContent = score.toString();
  scoreBand.textContent   = band;
  scoreNumber.style.color = color;
  scoreBand.style.color   = color;
  animateRing(score, color);
}

// ════════════════════════════════════════════════════════════════════
// CARD RENDERING
// ════════════════════════════════════════════════════════════════════

const STATUS_BADGE = {
  pass: `<span class="badge badge-pass">Pass</span>`,
  warn: `<span class="badge badge-warn">Warn</span>`,
  fail: `<span class="badge badge-fail">Fail</span>`,
  skip: `<span class="badge badge-skip">Skip</span>`,
};

/** Render a completed module result into its card */
function renderCard(moduleId, result, delay = 0) {
  const statusEl = $(`status-${moduleId}`);
  const bodyEl   = $(`body-${moduleId}`);
  const cardEl   = $(`card-${moduleId}`);
  if (!statusEl || !bodyEl || !cardEl) return;

  // Badge + status
  statusEl.innerHTML = STATUS_BADGE[result.status] ?? STATUS_BADGE.skip;

  // Show hidden cards (CMS, darkweb) when they have results
  if (moduleId === 'cms' || moduleId === 'darkweb') {
    if (result.status !== 'skip') {
      cardEl.classList.remove('hidden');
    }
  }

  // Expanded body — shows detail + raw values
  const rawLines = result.raw
    ? Object.entries(result.raw)
        .filter(([k]) => k !== 'error' && k !== 'verifications' && k !== 'issues')
        .map(([k, v]) => {
          let val;
          if (Array.isArray(v)) {
            val = v.length > 0 ? v.join(', ') : 'None';
          } else if (typeof v === 'object' && v !== null) {
            val = JSON.stringify(v);
          } else {
            val = String(v);
          }
          // Truncate very long values
          if (val.length > 120) val = val.substring(0, 117) + '…';
          return `<div class="raw-row"><span class="raw-key">${escapeHTML(k)}</span><span class="raw-val">${escapeHTML(val)}</span></div>`;
        })
        .join('')
    : '';

  bodyEl.innerHTML = `
    <p class="card-detail">${escapeHTML(result.detail ?? '')}</p>
    ${rawLines ? `<div class="raw-block">${rawLines}</div>` : ''}
  `;

  // Staggered slide-in animation
  setTimeout(() => {
    cardEl.classList.add('card-ready');
    cardEl.classList.add(`status-${result.status}`);
  }, delay);
}

/** Escape HTML to prevent XSS from URL/domain data */
function escapeHTML(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Set all cards to loading state */
function resetCards() {
  MODULE_IDS.forEach(id => {
    const card = $(`card-${id}`);
    const body = $(`body-${id}`);
    const status = $(`status-${id}`);
    if (card) {
      card.classList.remove('card-ready', 'status-pass', 'status-warn', 'status-fail', 'status-skip', 'card-open');
    }
    if (body) body.innerHTML = '';
    if (status) status.innerHTML = `<span class="spinner"></span>`;
  });
}

// ════════════════════════════════════════════════════════════════════
// COLLAPSIBLE CARDS — Toggle expand / collapse
// ════════════════════════════════════════════════════════════════════

function setupCardToggles() {
  document.querySelectorAll('.module-card').forEach(card => {
    const header = card.querySelector('.card-header');
    header.addEventListener('click', () => {
      const isOpen = card.classList.contains('card-open');
      // Close all others for accordion feel
      document.querySelectorAll('.module-card.card-open').forEach(c => c.classList.remove('card-open'));
      if (!isOpen) card.classList.add('card-open');
    });
  });
}

// ════════════════════════════════════════════════════════════════════
// IMPERSONATION ALERT
// ════════════════════════════════════════════════════════════════════

function showImpersonationAlert(scoreResult) {
  const alertEl = $('impersonation-alert');
  if (!alertEl) return;

  if (scoreResult.impersonationDetected) {
    alertEl.classList.remove('hidden');
    const brandEl = $('impersonation-brand');
    // Extract brand info from authoritative result if available
    if (brandEl && currentResults?.authoritative?.raw?.impersonation) {
      const imp = currentResults.authoritative.raw.impersonation;
      brandEl.textContent = `Impersonating "${imp.brandName}" (${imp.canonicalDomain}) — Confidence: ${imp.confidence}%`;
    }
  } else {
    alertEl.classList.add('hidden');
  }
}

// ════════════════════════════════════════════════════════════════════
// MAIN SCAN FLOW — Always full scan
// ════════════════════════════════════════════════════════════════════

async function getActiveTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs?.[0] ?? null);
    });
  });
}

async function runScan(forceRefresh = false) {
  if (!currentHostname) return;

  setScanning();
  resetCards();
  rescanBtn.disabled = true;

  try {
    // Get pageMeta from content script
    let pageMeta = null;
    try {
      const resp = await chrome.tabs.sendMessage(currentTabId, { type: 'GET_HOSTNAME' });
      pageMeta = resp?.pageMeta;
    } catch (e) {
      console.warn('Could not get pageMeta:', e);
    }

    const response = await chrome.runtime.sendMessage({
      type: 'SCAN',
      url: currentUrl,
      hostname: currentHostname,
      tabId: currentTabId,
      forceRefresh,
      pageMeta,
    });

    if (!response?.success) {
      showError(response?.error ?? 'Scan failed');
      return;
    }

    currentResults = response.results;
    const scoreResult = currentResults._score;

    // Display score ring
    displayScore(scoreResult.score, scoreResult.band, scoreResult.color);

    // Show impersonation alert if detected
    showImpersonationAlert(scoreResult);

    // Render each module card with staggered delays
    MODULE_IDS.forEach((id, i) => {
      const result = currentResults[id];
      if (result) {
        renderCard(id, result, i * 80);
      }
    });

  } catch (err) {
    showError(err.message);
  } finally {
    rescanBtn.disabled = false;
  }
}

function showError(msg) {
  ringPulse.classList.remove('pulsing');
  scoreNumber.textContent = '!';
  scoreBand.textContent   = 'Error';
  scoreNumber.style.color = '#ff3b3b';
  console.error('[TrustLens]', msg);
}

// ════════════════════════════════════════════════════════════════════
// CLIPBOARD EXPORT
// ════════════════════════════════════════════════════════════════════

function buildPlainTextReport() {
  if (!currentResults) return 'No scan results available.';

  const score = currentResults._score;
  const lines = [
    `═══════════════════════════════════════════`,
    `  TrustLens Trust Report`,
    `═══════════════════════════════════════════`,
    `Domain:      ${currentHostname}`,
    `Generated:   ${new Date().toLocaleString()}`,
    `Trust Score: ${score.score}/100 (${score.band})`,
    `Scan Mode:   Full`,
    score.impersonationDetected ? `ALERT:       ⚠ IMPERSONATION DETECTED` : '',
    `${'─'.repeat(43)}`,
    '',
  ].filter(Boolean);

  MODULE_IDS.forEach(id => {
    const r = currentResults[id];
    if (!r) return;
    const statusIcon = { pass: '✓', warn: '⚠', fail: '✗', skip: '○' }[r.status] ?? '?';
    lines.push(`  [${statusIcon}] ${(r.label ?? id).padEnd(27)} ${(r.status ?? 'skip').toUpperCase()}`);
    if (r.detail) {
      const words = r.detail.split(' ');
      let line = '      ';
      for (const word of words) {
        if ((line + word).length > 60) {
          lines.push(line.trimEnd());
          line = '      ';
        }
        line += word + ' ';
      }
      if (line.trim()) lines.push(line.trimEnd());
    }
    lines.push('');
  });

  lines.push(`${'─'.repeat(43)}`);
  lines.push(`  Generated by TrustLens v1.1`);

  return lines.join('\n');
}

copyBtn.addEventListener('click', async () => {
  const text = buildPlainTextReport();
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.textContent = '✓ Copied!';
    copyBtn.classList.add('copied');
    setTimeout(() => {
      copyBtn.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy Report`;
      copyBtn.classList.remove('copied');
    }, 2000);
  } catch {
    copyBtn.textContent = 'Failed';
  }
});

// ════════════════════════════════════════════════════════════════════
// RESCAN BUTTON
// ════════════════════════════════════════════════════════════════════

rescanBtn.addEventListener('click', () => runScan(true));

// ════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════

async function init() {
  await checkOnboarding();
  setupCardToggles();

  // Get active tab info
  const tab = await getActiveTab();
  if (!tab) {
    showError('No active tab found');
    return;
  }

  currentTabId = tab.id;
  currentUrl   = tab.url ?? '';

  try {
    const parsed = new URL(currentUrl);
    currentHostname = parsed.hostname;
  } catch {
    currentHostname = '';
  }

  if (!currentHostname) {
    domainText.textContent = 'No website';
    scoreNumber.textContent = '—';
    scoreBand.textContent = 'Open a web page to scan';
    ringPulse.classList.remove('pulsing');
    return;
  }

  domainText.textContent = currentHostname;
  await runScan(false);
}

init().catch(err => console.error('[TrustLens init]', err));
