/**
 * content.js — TrustLens Content Script
 *
 * Responsibilities:
 *   - Reads page metadata (CMS, contact info, gov claims)
 *   - Posts hostname to background on page load
 *   - Listens for SCAN_STARTED and SCAN_RESULTS from background
 *   - Renders a compact auto-popup overlay showing scan progress & results
 *   - Shows risk alert banner for dangerous sites
 *   - Auto-popup appears on every page visit, auto-dismisses after 8s
 */

(function () {
  'use strict';

  const hostname = window.location.hostname;
  if (!hostname) return;

  // ── Page Analysis ─────────────────────────────────────────────────────────
  function analyzePage() {
    const meta = {
      isWordPress: false,
      hasContact: false,
      claimsGov: false,
    };

    // 1. WordPress Detection
    const generator = document.querySelector('meta[name="generator"]')?.content || '';
    if (generator.toLowerCase().includes('wordpress') || 
        document.querySelector('link[href*="wp-content"]') || 
        document.querySelector('script[src*="wp-includes"]')) {
      meta.isWordPress = true;
    }

    // 2. Contact Info Search
    const bodyText = document.body.innerText.toLowerCase();
    const hasEmail = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(bodyText);
    const hasPhone = /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/.test(bodyText);
    const hasContactLink = !!document.querySelector('a[href*="contact"], a[href*="about"]');
    
    if (hasEmail || hasPhone || hasContactLink) {
      meta.hasContact = true;
    }

    // 3. Government Claim Check
    const title = document.title.toLowerCase();
    const metaDesc = document.querySelector('meta[name="description"]')?.content?.toLowerCase() || '';
    if (title.includes('government of') || title.includes('official portal') || 
        metaDesc.includes('government of') || metaDesc.includes('official portal')) {
      meta.claimsGov = true;
    }

    return meta;
  }

  const pageMeta = analyzePage();

  // Notify background
  chrome.runtime.sendMessage({
    type: 'PAGE_HOSTNAME',
    hostname,
    href: window.location.href,
    pageMeta,
  }).catch(() => {});

  // ── Style Injection ───────────────────────────────────────────────────────
  function injectStyles() {
    if (document.getElementById('trustlens-styles')) return;
    const style = document.createElement('style');
    style.id = 'trustlens-styles';
    style.textContent = `
      @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');

      #trustlens-popup-overlay {
        position: fixed;
        top: 16px;
        right: 16px;
        z-index: 2147483646;
        width: 340px;
        background: #12141d;
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 14px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(0,229,255,0.06);
        font-family: 'DM Sans', system-ui, -apple-system, sans-serif;
        color: #e2e8f0;
        overflow: hidden;
        animation: tl-slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        transition: opacity 0.3s ease, transform 0.3s ease;
      }

      #trustlens-popup-overlay.tl-hiding {
        opacity: 0;
        transform: translateY(-12px) scale(0.96);
        pointer-events: none;
      }

      @keyframes tl-slideIn {
        from { opacity: 0; transform: translateY(-20px) scale(0.94); }
        to   { opacity: 1; transform: translateY(0) scale(1); }
      }

      .tl-popup-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 14px;
        background: rgba(0,229,255,0.04);
        border-bottom: 1px solid rgba(255,255,255,0.06);
      }

      .tl-popup-brand {
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .tl-popup-brand svg {
        flex-shrink: 0;
      }

      .tl-popup-brand-name {
        font-size: 13px;
        font-weight: 700;
        color: #e2e8f0;
        letter-spacing: 0.3px;
      }

      .tl-popup-close {
        background: transparent;
        border: 1px solid rgba(255,255,255,0.06);
        color: #6b7280;
        width: 24px;
        height: 24px;
        border-radius: 6px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 14px;
        transition: all 0.2s;
      }

      .tl-popup-close:hover {
        color: #e2e8f0;
        border-color: rgba(255,255,255,0.15);
        background: rgba(255,255,255,0.05);
      }

      .tl-popup-body {
        padding: 16px 14px;
      }

      .tl-popup-score-row {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 14px;
      }

      .tl-popup-ring-wrap {
        position: relative;
        width: 64px;
        height: 64px;
        flex-shrink: 0;
      }

      .tl-popup-ring-wrap svg {
        width: 100%;
        height: 100%;
      }

      .tl-ring-track {
        fill: none;
        stroke: #1e2235;
        stroke-width: 6;
      }

      .tl-ring-fill {
        fill: none;
        stroke: #00e5ff;
        stroke-width: 6;
        stroke-linecap: round;
        stroke-dasharray: 176;
        stroke-dashoffset: 176;
        transition: stroke-dashoffset 1s cubic-bezier(0.34, 1.56, 0.64, 1),
                    stroke 0.5s ease;
      }

      .tl-ring-pulse {
        fill: none;
        stroke: #00e5ff;
        stroke-width: 2;
        opacity: 0;
      }

      .tl-ring-pulse.tl-pulsing {
        animation: tl-ringPulse 1.4s ease-in-out infinite;
      }

      @keyframes tl-ringPulse {
        0%   { opacity: 0; r: 28; stroke-width: 2; }
        40%  { opacity: 0.3; }
        100% { opacity: 0; r: 34; stroke-width: 0; }
      }

      .tl-score-text {
        position: absolute;
        inset: 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
      }

      .tl-score-num {
        font-size: 18px;
        font-weight: 700;
        color: #00e5ff;
        line-height: 1;
      }

      .tl-score-label {
        font-size: 8px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #94a3b8;
        margin-top: 2px;
      }

      .tl-popup-info {
        flex: 1;
        min-width: 0;
      }

      .tl-popup-domain {
        font-size: 12px;
        font-weight: 600;
        color: #00e5ff;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        margin-bottom: 4px;
      }

      .tl-popup-verdict {
        font-size: 13px;
        font-weight: 600;
        line-height: 1.3;
        margin-bottom: 2px;
      }

      .tl-popup-mode {
        font-size: 10px;
        color: #6b7280;
      }

      .tl-popup-checks {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }

      .tl-check-row {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 8px;
        background: rgba(255,255,255,0.02);
        border-radius: 7px;
        border: 1px solid rgba(255,255,255,0.04);
        font-size: 11px;
        transition: background 0.2s;
      }

      .tl-check-row:hover {
        background: rgba(255,255,255,0.04);
      }

      .tl-check-icon {
        width: 16px;
        height: 16px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 9px;
        flex-shrink: 0;
        font-weight: 700;
      }

      .tl-check-icon.tl-pass {
        background: rgba(0,229,255,0.12);
        color: #00e5ff;
      }
      .tl-check-icon.tl-warn {
        background: rgba(255,179,0,0.12);
        color: #ffb300;
      }
      .tl-check-icon.tl-fail {
        background: rgba(255,59,59,0.12);
        color: #ff3b3b;
      }
      .tl-check-icon.tl-skip {
        background: rgba(107,114,128,0.12);
        color: #6b7280;
      }
      .tl-check-icon.tl-loading {
        background: rgba(0,229,255,0.08);
        color: #00e5ff;
        animation: tl-spin 0.7s linear infinite;
      }

      @keyframes tl-spin {
        to { transform: rotate(360deg); }
      }

      .tl-check-name {
        color: #94a3b8;
        flex: 1;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .tl-check-badge {
        font-size: 9px;
        font-weight: 700;
        padding: 1px 5px;
        border-radius: 3px;
        text-transform: uppercase;
        letter-spacing: 0.3px;
      }
      
      .tl-check-badge.tl-badge-pass { background: rgba(0,229,255,0.12); color: #00e5ff; }
      .tl-check-badge.tl-badge-warn { background: rgba(255,179,0,0.12); color: #ffb300; }
      .tl-check-badge.tl-badge-fail { background: rgba(255,59,59,0.12); color: #ff3b3b; }
      .tl-check-badge.tl-badge-skip { background: rgba(107,114,128,0.12); color: #6b7280; }

      .tl-popup-footer {
        padding: 8px 14px;
        border-top: 1px solid rgba(255,255,255,0.04);
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 10px;
        color: #4b5563;
      }

      .tl-popup-footer a {
        color: #00e5ff;
        text-decoration: none;
        cursor: pointer;
        transition: opacity 0.2s;
      }
      .tl-popup-footer a:hover { opacity: 0.7; }

      .tl-progress-bar {
        width: 100%;
        height: 2px;
        background: #1e2235;
        overflow: hidden;
      }

      .tl-progress-fill {
        height: 100%;
        background: linear-gradient(90deg, #00e5ff, #0091ea);
        width: 0%;
        transition: width 0.5s ease;
        animation: tl-progressPulse 1.5s ease infinite;
      }

      @keyframes tl-progressPulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
      }

      .tl-progress-fill.tl-done {
        width: 100% !important;
        animation: none;
        opacity: 1;
      }

      .tl-auto-dismiss-bar {
        height: 2px;
        background: rgba(0,229,255,0.3);
        width: 100%;
        animation: tl-shrinkBar 8s linear forwards;
      }

      @keyframes tl-shrinkBar {
        from { width: 100%; }
        to   { width: 0%; }
      }

      /* Risk Alert Banner */
      #trustlens-alert {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        z-index: 2147483647;
        background: linear-gradient(90deg, #d32f2f, #ff3b3b);
        color: white;
        padding: 12px 20px;
        text-align: center;
        font-family: 'DM Sans', system-ui, sans-serif;
        font-weight: 600;
        font-size: 14px;
        box-shadow: 0 4px 16px rgba(255,59,59,0.4);
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 12px;
        animation: tl-slideDown 0.4s ease;
      }

      @keyframes tl-slideDown {
        from { transform: translateY(-100%); }
        to   { transform: translateY(0); }
      }

      #trustlens-alert button {
        background: rgba(0,0,0,0.25);
        border: 1px solid rgba(255,255,255,0.3);
        color: white;
        padding: 5px 14px;
        cursor: pointer;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 600;
        transition: background 0.2s;
      }

      #trustlens-alert button:hover {
        background: rgba(0,0,0,0.4);
      }
    `;
    document.head.appendChild(style);
  }

  // ── Auto-Popup Rendering ──────────────────────────────────────────────────

  const RING_CIRC = 176; // 2π × 28
  const MODULE_DISPLAY = [
    { key: 'authoritative', label: 'Authoritative Verification' },
    { key: 'identity', label: 'Identity & Ownership' },
    { key: 'ssl',      label: 'SSL Certificate' },
    { key: 'dns',      label: 'DNS & Email Security' },
    { key: 'domain',   label: 'Domain Structure' },
    { key: 'tld',      label: 'TLD Risk' },
    { key: 'age',      label: 'Domain Age' },
    { key: 'sb',       label: 'Safe Browsing' },
    { key: 'live',     label: 'Live Check' },
  ];

  const STATUS_ICONS = {
    pass: '✓',
    warn: '!',
    fail: '✗',
    skip: '—',
    loading: '◌',
  };

  let autoDismissTimer = null;
  let popupEl = null;

  function removePopup() {
    if (popupEl) {
      popupEl.classList.add('tl-hiding');
      setTimeout(() => {
        popupEl?.remove();
        popupEl = null;
      }, 300);
    }
    if (autoDismissTimer) {
      clearTimeout(autoDismissTimer);
      autoDismissTimer = null;
    }
  }

  function showScanningPopup(host) {
    injectStyles();
    removePopup();

    const el = document.createElement('div');
    el.id = 'trustlens-popup-overlay';
    el.innerHTML = `
      <div class="tl-popup-header">
        <div class="tl-popup-brand">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span class="tl-popup-brand-name">TrustLens</span>
        </div>
        <button class="tl-popup-close" id="tl-close-btn">×</button>
      </div>
      <div class="tl-progress-bar"><div class="tl-progress-fill" id="tl-progress" style="width:30%"></div></div>
      <div class="tl-popup-body">
        <div class="tl-popup-score-row">
          <div class="tl-popup-ring-wrap">
            <svg viewBox="0 0 64 64">
              <circle class="tl-ring-track" cx="32" cy="32" r="28"/>
              <circle class="tl-ring-fill" id="tl-ring" cx="32" cy="32" r="28" 
                stroke-dasharray="${RING_CIRC}" stroke-dashoffset="${RING_CIRC}"
                transform="rotate(-90 32 32)"/>
              <circle class="tl-ring-pulse tl-pulsing" cx="32" cy="32" r="28"/>
            </svg>
            <div class="tl-score-text">
              <span class="tl-score-num" id="tl-score-num">—</span>
              <span class="tl-score-label" id="tl-score-label">Scanning</span>
            </div>
          </div>
          <div class="tl-popup-info">
            <div class="tl-popup-domain">${escapeHTML(host)}</div>
            <div class="tl-popup-verdict" id="tl-verdict" style="color:#00e5ff">Analyzing website trust…</div>
            <div class="tl-popup-mode" id="tl-mode">Full scan in progress</div>
          </div>
        </div>
        <div class="tl-popup-checks" id="tl-checks">
          ${MODULE_DISPLAY.map(m => `
            <div class="tl-check-row" id="tl-row-${m.key}">
              <span class="tl-check-icon tl-loading">◌</span>
              <span class="tl-check-name">${m.label}</span>
              <span class="tl-check-badge tl-badge-skip">…</span>
            </div>
          `).join('')}
        </div>
      </div>
      <div class="tl-popup-footer">
        <span>TrustLens v1.0</span>
        <a id="tl-open-ext">Open full report ›</a>
      </div>
    `;

    document.body.appendChild(el);
    popupEl = el;

    // Close button
    document.getElementById('tl-close-btn').addEventListener('click', removePopup);

    // Open extension popup link
    document.getElementById('tl-open-ext').addEventListener('click', () => {
      // Can't programmatically open popup, but can scroll to top
      removePopup();
    });
  }

  function showResultsPopup(results, scoreData, host) {
    injectStyles();

    // If popup doesn't exist, create it
    if (!popupEl) {
      showScanningPopup(host);
    }

    // Update progress bar
    const progressEl = document.getElementById('tl-progress');
    if (progressEl) {
      progressEl.style.width = '100%';
      progressEl.classList.add('tl-done');
    }

    // Update ring
    const ringEl = document.getElementById('tl-ring');
    if (ringEl) {
      const offset = RING_CIRC - (scoreData.score / 100) * RING_CIRC;
      ringEl.style.strokeDashoffset = offset.toString();
      ringEl.style.stroke = scoreData.color;
    }

    // Remove pulse
    const pulseEl = popupEl?.querySelector('.tl-ring-pulse');
    if (pulseEl) pulseEl.classList.remove('tl-pulsing');

    // Update score
    const scoreNumEl = document.getElementById('tl-score-num');
    if (scoreNumEl) {
      scoreNumEl.textContent = scoreData.score.toString();
      scoreNumEl.style.color = scoreData.color;
    }

    const scoreLabelEl = document.getElementById('tl-score-label');
    if (scoreLabelEl) {
      scoreLabelEl.textContent = scoreData.band;
      scoreLabelEl.style.color = scoreData.color;
    }

    // Update verdict
    const verdictEl = document.getElementById('tl-verdict');
    if (verdictEl) {
      let verdictText;
      if (scoreData.score >= 80) verdictText = 'This site appears trustworthy';
      else if (scoreData.score >= 60) verdictText = 'This site is moderately safe';
      else if (scoreData.score >= 40) verdictText = 'Proceed with caution';
      else if (scoreData.score >= 20) verdictText = 'This site shows risk signals';
      else verdictText = 'This site may be dangerous';
      
      verdictEl.textContent = verdictText;
      verdictEl.style.color = scoreData.color;
    }

    // Update mode label
    const modeEl = document.getElementById('tl-mode');
    if (modeEl) {
      let modeText = 'Full scan complete';
      if (scoreData.impersonationDetected) {
        modeText = '⚠ IMPERSONATION DETECTED — Full scan complete';
      }
      modeEl.textContent = modeText;
      if (scoreData.impersonationDetected) modeEl.style.color = '#ff3b3b';
    }

    // Update each check row
    MODULE_DISPLAY.forEach(m => {
      const row = document.getElementById(`tl-row-${m.key}`);
      if (!row) return;

      const result = results[m.key];
      const status = result?.status ?? 'skip';
      
      const iconEl = row.querySelector('.tl-check-icon');
      const badgeEl = row.querySelector('.tl-check-badge');

      if (iconEl) {
        iconEl.className = `tl-check-icon tl-${status}`;
        iconEl.textContent = STATUS_ICONS[status] || '—';
      }

      if (badgeEl) {
        badgeEl.className = `tl-check-badge tl-badge-${status}`;
        badgeEl.textContent = status.toUpperCase();
      }
    });

    // Add auto-dismiss bar and timer (8 seconds for safe, 15 seconds for risky)
    const dismissTime = scoreData.score >= 60 ? 8000 : 15000;

    // Remove existing dismiss bar
    const existingBar = popupEl?.querySelector('.tl-auto-dismiss-bar');
    if (existingBar) existingBar.remove();

    // Add new dismiss bar before footer
    const footer = popupEl?.querySelector('.tl-popup-footer');
    if (footer) {
      const dismissBar = document.createElement('div');
      dismissBar.className = 'tl-auto-dismiss-bar';
      dismissBar.style.animationDuration = `${dismissTime}ms`;
      footer.parentNode.insertBefore(dismissBar, footer);
    }

    // Auto-dismiss
    if (autoDismissTimer) clearTimeout(autoDismissTimer);
    autoDismissTimer = setTimeout(removePopup, dismissTime);

    // Pause auto-dismiss on hover
    popupEl?.addEventListener('mouseenter', () => {
      if (autoDismissTimer) {
        clearTimeout(autoDismissTimer);
        autoDismissTimer = null;
      }
      const bar = popupEl?.querySelector('.tl-auto-dismiss-bar');
      if (bar) bar.style.animationPlayState = 'paused';
    });

    popupEl?.addEventListener('mouseleave', () => {
      const bar = popupEl?.querySelector('.tl-auto-dismiss-bar');
      if (bar) bar.style.animationPlayState = 'running';
      autoDismissTimer = setTimeout(removePopup, 4000);
    });
  }

  function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ── Risk Alert Banner ─────────────────────────────────────────────────────

  function showRiskyAlert(score, band) {
    if (document.getElementById('trustlens-alert')) return;
    const alert = document.createElement('div');
    alert.id = 'trustlens-alert';
    injectStyles();
    alert.innerHTML = `
      <span>⚠️ TrustLens Alert: This site has a <strong>${band}</strong> Trust Score of <strong>${score}%</strong>. Proceed with caution.</span>
      <button id="trustlens-close">Dismiss</button>
    `;
    document.body.prepend(alert);
    document.getElementById('trustlens-close').onclick = () => alert.remove();
  }

  // ── Message Listener ──────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'GET_HOSTNAME') {
      sendResponse({ hostname, href: window.location.href, protocol: window.location.protocol, pageMeta });
      return true;
    }

    if (msg.type === 'SCAN_STARTED') {
      showScanningPopup(msg.hostname || hostname);
    }

    if (msg.type === 'SCAN_RESULTS') {
      showResultsPopup(msg.results, msg.score, msg.hostname || hostname);
    }

    if (msg.type === 'RISK_ALERT') {
      showRiskyAlert(msg.score, msg.band);
    }
  });
}());
