/**
 * options.js — TrustLens Settings Page Controller
 *
 * Handles:
 *   1. Safe Browsing API key — save / remove / show-hide
 *   2. Default scan mode — fast vs full
 *   3. Cache clear — sends CLEAR_CACHE message to background
 */

// ── DOM refs ─────────────────────────────────────────────────────────────────
const apiKeyInput    = document.getElementById('api-key-input');
const toggleVisBtn   = document.getElementById('toggle-key-vis');
const saveKeyBtn     = document.getElementById('save-key-btn');
const clearKeyBtn    = document.getElementById('clear-key-btn');
const keyStatus      = document.getElementById('key-status');

const modeFastRadio  = document.getElementById('mode-fast');
const modeFullRadio  = document.getElementById('mode-full');
const saveModeBtn    = document.getElementById('save-mode-btn');
const modeStatus     = document.getElementById('mode-status');

const clearCacheBtn  = document.getElementById('clear-cache-btn');
const cacheStatus    = document.getElementById('cache-status');

// ── Utility: show a status message that fades after 3s ───────────────────────
function showStatus(el, msg, type = 'success') {
  el.textContent = msg;
  el.className = `status-message ${type}`;
  clearTimeout(el._timer);
  el._timer = setTimeout(() => {
    el.textContent = '';
    el.className = 'status-message';
  }, 3500);
}

// ════════════════════════════════════════════════════════════════════
// 1. API KEY — Save / Remove / Visibility Toggle
// ════════════════════════════════════════════════════════════════════

/** Load existing key from storage and populate input (masked) */
async function loadApiKey() {
  const { safeBrowsingKey } = await chrome.storage.sync.get('safeBrowsingKey');
  if (safeBrowsingKey) {
    // Show masked version — don't expose key in plain text by default
    apiKeyInput.value = safeBrowsingKey;
    apiKeyInput.type = 'password';
  }
}

/** Save key to chrome.storage.sync */
saveKeyBtn.addEventListener('click', async () => {
  const key = apiKeyInput.value.trim();
  if (!key) {
    showStatus(keyStatus, 'Please enter an API key.', 'error');
    return;
  }
  try {
    await chrome.storage.sync.set({ safeBrowsingKey: key });
    showStatus(keyStatus, '✓ API key saved successfully.', 'success');
  } catch (err) {
    showStatus(keyStatus, `Error saving key: ${err.message}`, 'error');
  }
});

/** Remove key from storage */
clearKeyBtn.addEventListener('click', async () => {
  try {
    await chrome.storage.sync.remove('safeBrowsingKey');
    apiKeyInput.value = '';
    showStatus(keyStatus, 'API key removed.', 'warn');
  } catch (err) {
    showStatus(keyStatus, `Error removing key: ${err.message}`, 'error');
  }
});

/** Toggle password visibility */
let keyVisible = false;
toggleVisBtn.addEventListener('click', () => {
  keyVisible = !keyVisible;
  apiKeyInput.type = keyVisible ? 'text' : 'password';
  // Swap icon
  const icon = document.getElementById('eye-icon');
  if (keyVisible) {
    // Eye-off icon
    icon.innerHTML = `
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
      <line x1="1" y1="1" x2="23" y2="23"/>`;
  } else {
    // Eye icon
    icon.innerHTML = `
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
      <circle cx="12" cy="12" r="3"/>`;
  }
});

// ════════════════════════════════════════════════════════════════════
// 2. SCAN MODE — Default fast vs full
// ════════════════════════════════════════════════════════════════════

async function loadScanMode() {
  const { defaultFastMode } = await chrome.storage.sync.get('defaultFastMode');
  // undefined → default to fast
  if (defaultFastMode === false) {
    modeFullRadio.checked = true;
  } else {
    modeFastRadio.checked = true;
  }
}

saveModeBtn.addEventListener('click', async () => {
  const isFast = modeFastRadio.checked;
  try {
    await chrome.storage.sync.set({ defaultFastMode: isFast });
    showStatus(modeStatus, `✓ Default set to ${isFast ? 'Fast' : 'Full'} Mode.`, 'success');
  } catch (err) {
    showStatus(modeStatus, `Error saving preference: ${err.message}`, 'error');
  }
});

// ════════════════════════════════════════════════════════════════════
// 3. CACHE — Clear session cache via background message
// ════════════════════════════════════════════════════════════════════

clearCacheBtn.addEventListener('click', async () => {
  try {
    // Send message to background service worker to clear cache
    const response = await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' });
    if (response?.success) {
      showStatus(cacheStatus, '✓ Cache cleared successfully.', 'success');
    } else {
      showStatus(cacheStatus, 'Cache clear encountered an issue.', 'warn');
    }
  } catch (err) {
    // If background is not running, clear directly from options page
    try {
      await chrome.storage.session.clear();
      showStatus(cacheStatus, '✓ Cache cleared.', 'success');
    } catch {
      showStatus(cacheStatus, `Error: ${err.message}`, 'error');
    }
  }
});

// ════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════

async function init() {
  await Promise.all([loadApiKey(), loadScanMode()]);
}

init().catch(err => console.error('[TrustLens Options]', err));
