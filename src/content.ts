// =============================================================================
// SentinelAI — Content Script
// Cosmetic filtering: hides known ad/tracker DOM elements using specific,
// curated CSS selectors. Does NOT use broad word-matching.
//
// Respects TWO conditions before filtering:
//   1. Global protection is ON (chrome.storage adBlockingEnabled === true)
//   2. Current site is NOT allowlisted
//
// Uses MutationObserver + requestAnimationFrame batching.
//
// Also performs automatic phishing scanning on top-level navigation.
// Warning overlay is shown only for riskScore >= 35.
// =============================================================================

// ---------------------------------------------------------------------------
// Specific, curated cosmetic selectors — targeting known ad-network
// class names, generated IDs, and iframe src patterns only.
// NOT using broad word-match selectors like [class*="ad"] or [id*="banner"].
// ---------------------------------------------------------------------------
const AD_SELECTORS: readonly string[] = [
  // Google / DoubleClick
  "ins.adsbygoogle",
  "[id^='google_ads_iframe']",
  "[id^='div-gpt-ad']",
  "iframe[src*='googlesyndication.com']",
  "iframe[src*='doubleclick.net']",
  "iframe[src*='googleadservices.com']",

  // Outbrain
  "[id^='outbrain_widget']",
  "div.ob-widget",
  "div.ob-smartfeed-wrapper",

  // Taboola
  "div[id^='taboola-']",
  "div.trc_related_container",
  "div[class*='tbl-feed-widget']",

  // Media.net
  "div[id^='mNCC']",
  "div[id^='mNAW']",
  "iframe[src*='media.net']",

  // Criteo
  "div.cto_iframe",
  "iframe[src*='criteo.com']",

  // Xandr / AppNexus
  "iframe[src*='adnxs.com']",

  // Amazon ads
  "iframe[src*='amazon-adsystem.com']",
  "[id^='amzn_assoc_ad']",

  // Trade Desk
  "iframe[src*='adsrvr.org']",

  // Quantserve pixel
  "img[src*='quantserve.com']",

  // ComScore / ScorecardResearch
  "img[src*='scorecardresearch.com']",
  "img[src*='b.scorecardresearch.com']",

  // PubMatic
  "iframe[src*='pubmatic.com']",

  // Rubicon / Magnite
  "iframe[src*='rubiconproject.com']",

  // OpenX
  "iframe[src*='openx.net']",

  // Smaato
  "iframe[src*='smaato.net']",

  // Skimlinks
  "span.skimlinks-unlinked",
  "a[data-skimlinks-tracking]",

  // Facebook pixel
  "img[src*='pixel.facebook.com']",

  // Hotjar
  "iframe[src*='hotjar.com']",

  // GPT/Prebid-generated containers (framework-generated IDs, not page content)
  "[id^='ad-slot-']",
  "[id^='ad_slot_']",
  "[id^='dfp-ad-']",
  "[class='dfp-tag-wrapper']",
  "div[data-google-query-id]",
];

// Pre-build combined selector string for efficient querySelectorAll.
// The warning overlay is excluded via :not([data-sentinel-phishing-warning])
// so cosmetic filtering never accidentally hides our own UI element.
const COMBINED_SELECTOR =
  AD_SELECTORS.map(s => `${s}:not([data-sentinel-phishing-warning])`).join(",");
const HIDDEN_ATTR = "data-sentinel-hidden";

// ---------------------------------------------------------------------------
// State — cosmetic filtering
// ---------------------------------------------------------------------------
let cosmeticEnabled = false; // starts false; set to true only after both checks pass
let observerRunning = false;

// ---------------------------------------------------------------------------
// Element hiding
// ---------------------------------------------------------------------------
function hideElement(el: Element): void {
  if (el.hasAttribute(HIDDEN_ATTR)) return;
  (el as HTMLElement).style.setProperty("display", "none", "important");
  el.setAttribute(HIDDEN_ATTR, "1");
}

function scanAndHide(root: Document | Element = document): void {
  if (!cosmeticEnabled) return;
  try {
    root.querySelectorAll(COMBINED_SELECTOR).forEach(hideElement);
  } catch {
    // querySelectorAll can throw on some custom elements
  }
}

// ---------------------------------------------------------------------------
// MutationObserver — batched via requestAnimationFrame
// ---------------------------------------------------------------------------
let pendingMutation = false;

function scheduleScan(): void {
  if (!cosmeticEnabled || pendingMutation) return;
  pendingMutation = true;
  requestAnimationFrame(() => {
    pendingMutation = false;
    scanAndHide();
  });
}

const observer = new MutationObserver((mutations) => {
  if (!cosmeticEnabled) return;
  const hasAddedNodes = mutations.some(m => m.addedNodes.length > 0);
  if (hasAddedNodes) scheduleScan();
});

function startObserver(): void {
  if (observerRunning) return;
  observerRunning = true;
  observer.observe(document.documentElement, { childList: true, subtree: true });
}

function stopObserver(): void {
  if (!observerRunning) return;
  observerRunning = false;
  observer.disconnect();
}

// ---------------------------------------------------------------------------
// Enable / disable cosmetic filtering
// ---------------------------------------------------------------------------
function enableCosmetic(): void {
  cosmeticEnabled = true;
  scanAndHide(); // initial pass
  startObserver();
}

function disableCosmetic(): void {
  cosmeticEnabled = false;
  stopObserver();
  // Note: we do NOT un-hide already-hidden elements.
  // Cosmetic changes are not reversible mid-page; a reload restores them.
}

// ---------------------------------------------------------------------------
// Storage change listener — react to toggle changes in real time
// ---------------------------------------------------------------------------
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if ("adBlockingEnabled" in changes) {
    const newValue = changes.adBlockingEnabled.newValue;
    if (newValue === false && cosmeticEnabled) {
      disableCosmetic();
    }
    // Re-check full conditions if protection was re-enabled
    if (newValue === true && !cosmeticEnabled) {
      checkAndStart();
    }
  }
  if ("adBlockAllowlist" in changes) {
    // Re-evaluate allowlist on change
    checkAndStart();
  }
});

// ---------------------------------------------------------------------------
// Start sequence: check both conditions before enabling
// ---------------------------------------------------------------------------
function checkAndStart(): void {
  const hostname = window.location.hostname.replace(/^www\./, "").toLowerCase();

  // Get both values in one storage call for efficiency
  chrome.storage.local.get(["adBlockingEnabled", "adBlockAllowlist"], (stored) => {
    if (chrome.runtime.lastError) return;

    const globallyEnabled: boolean = stored["adBlockingEnabled"] !== false; // default: true
    const allowlist: string[] = Array.isArray(stored["adBlockAllowlist"]) ? stored["adBlockAllowlist"] : [];

    // Check if current hostname is allowlisted (exact or parent domain match)
    const isAllowlisted = allowlist.some(entry => hostname === entry || hostname.endsWith("." + entry));

    if (globallyEnabled && !isAllowlisted) {
      if (!cosmeticEnabled) enableCosmetic();
    } else {
      if (cosmeticEnabled) disableCosmetic();
    }
  });
}

// ---------------------------------------------------------------------------
// Entry point — cosmetic filtering
// ---------------------------------------------------------------------------
checkAndStart();


// =============================================================================
// AUTOMATIC PHISHING SCANNER
// =============================================================================
// Runs ONCE per top-level URL (per page load / SPA navigation).
// Sends the URL to background.ts which calls /api/scan.
// Shows an in-page warning overlay ONLY when riskScore >= 35.
// Does NOT affect ad-blocker state, allowlist, or phishing model.
// Backend failures are fully silent — no false "safe" result is ever shown.
// =============================================================================

/** Risk thresholds — must match popup.ts */
const RISK_SUSPICIOUS = 35;
const RISK_DANGEROUS  = 65;

/** Attribute on the overlay root element — used to exclude it from cosmetic filtering */
const OVERLAY_ATTR = "data-sentinel-phishing-warning";

/** URL that was last submitted for scanning in this page context */
let lastScannedUrl = "";

// ---------------------------------------------------------------------------
// Private / local address guard — never scan non-public addresses
// ---------------------------------------------------------------------------
function isPrivateOrLocalUrl(url: string): boolean {
  // Check non-http schemes first on the raw string to avoid TS narrowing issues
  if (!url.startsWith("http://") && !url.startsWith("https://")) return true;
  try {
    const { hostname } = new URL(url);
    if (hostname === "localhost") return true;
    if (/^127\./.test(hostname)) return true;
    if (/^10\./.test(hostname)) return true;
    if (/^192\.168\./.test(hostname)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return true;
    if (/^::1$/.test(hostname)) return true;
    if (/^fd[0-9a-f]{2}:/i.test(hostname)) return true; // ULA IPv6
    return false;
  } catch {
    return true;
  }
}

// ---------------------------------------------------------------------------
// Overlay CSS — injected once as a <style> tag scoped to the sentinel namespace
// ---------------------------------------------------------------------------
const OVERLAY_CSS = `
[data-sentinel-phishing-warning] *,
[data-sentinel-phishing-warning] *::before,
[data-sentinel-phishing-warning] *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}
[data-sentinel-phishing-warning] {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 2147483647;
  font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  display: flex;
  justify-content: center;
  pointer-events: none;
}
.sai-panel {
  pointer-events: all;
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 14px 18px;
  margin: 10px;
  border-radius: 8px;
  max-width: 680px;
  width: 100%;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  box-shadow: 0 4px 24px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.07);
}
.sai-panel.sai-suspicious {
  background: linear-gradient(135deg, rgba(18,24,36,0.97) 0%, rgba(22,30,50,0.97) 100%);
  border-left: 3px solid #f5a623;
}
.sai-panel.sai-dangerous {
  background: linear-gradient(135deg, rgba(24,10,12,0.97) 0%, rgba(34,14,18,0.97) 100%);
  border-left: 3px solid #ff4557;
}
.sai-icon {
  flex-shrink: 0;
  width: 34px;
  height: 34px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 17px;
  font-weight: 800;
}
.sai-suspicious .sai-icon {
  background: rgba(245,166,35,0.14);
  color: #f5a623;
  border: 1px solid rgba(245,166,35,0.28);
}
.sai-dangerous .sai-icon {
  background: rgba(255,69,87,0.14);
  color: #ff4557;
  border: 1px solid rgba(255,69,87,0.28);
}
.sai-body { flex: 1; min-width: 0; }
.sai-brand {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 1.2px;
  text-transform: uppercase;
  margin-bottom: 2px;
}
.sai-suspicious .sai-brand { color: #f5a623; }
.sai-dangerous  .sai-brand { color: #ff4557; }
.sai-headline {
  font-size: 15px;
  font-weight: 700;
  color: #f0f0f0;
  margin-bottom: 1px;
}
.sai-host {
  font-size: 12px;
  color: rgba(200,210,220,0.68);
  font-family: 'Menlo', 'Consolas', monospace;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-bottom: 6px;
}
.sai-score-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.sai-badge {
  font-size: 11px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
  letter-spacing: 0.3px;
}
.sai-suspicious .sai-badge {
  background: rgba(245,166,35,0.14);
  color: #f5a623;
  border: 1px solid rgba(245,166,35,0.24);
}
.sai-dangerous .sai-badge {
  background: rgba(255,69,87,0.14);
  color: #ff4557;
  border: 1px solid rgba(255,69,87,0.24);
}
.sai-score-label {
  font-size: 11px;
  color: rgba(175,188,200,0.58);
}
.sai-reasons {
  display: flex;
  flex-direction: column;
  gap: 2px;
  margin-bottom: 10px;
  max-height: 58px;
  overflow: hidden;
}
.sai-reason {
  font-size: 11px;
  color: rgba(175,192,208,0.72);
  padding-left: 11px;
  position: relative;
}
.sai-reason::before {
  content: '';
  position: absolute;
  left: 2px;
  top: 50%;
  transform: translateY(-50%);
  width: 4px;
  height: 4px;
  border-radius: 50%;
}
.sai-suspicious .sai-reason::before { background: #f5a623; }
.sai-dangerous  .sai-reason::before { background: #ff4557; }
.sai-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.sai-btn {
  font-family: inherit;
  font-size: 12px;
  font-weight: 600;
  padding: 6px 14px;
  border-radius: 5px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: opacity 0.15s, transform 0.1s;
  letter-spacing: 0.2px;
}
.sai-btn:hover { opacity: 0.82; }
.sai-btn:active { transform: scale(0.97); }
.sai-btn-leave {
  background: rgba(255,255,255,0.06);
  color: #dce8f0;
  border-color: rgba(255,255,255,0.11);
}
.sai-dangerous .sai-btn-leave {
  background: rgba(255,69,87,0.16);
  color: #ffb3bb;
  border-color: rgba(255,69,87,0.28);
}
.sai-btn-continue {
  background: transparent;
  color: rgba(155,172,188,0.68);
  border-color: rgba(255,255,255,0.07);
}
.sai-close {
  flex-shrink: 0;
  background: none;
  border: none;
  cursor: pointer;
  color: rgba(155,172,188,0.48);
  font-size: 20px;
  line-height: 1;
  padding: 0 0 0 4px;
  align-self: flex-start;
  transition: color 0.15s;
  font-family: inherit;
}
.sai-close:hover { color: rgba(200,215,230,0.82); }
`;

let stylesInjected = false;

function injectOverlayStyles(): void {
  if (stylesInjected) return;
  stylesInjected = true;
  try {
    const style = document.createElement("style");
    style.setAttribute("data-sentinel-styles", "phishing-warning");
    style.textContent = OVERLAY_CSS;
    (document.head || document.documentElement).appendChild(style);
  } catch {
    // Non-fatal; overlay renders without styles in extreme edge cases
  }
}

// ---------------------------------------------------------------------------
// Overlay render / remove
// ---------------------------------------------------------------------------
type WarnLevel = "suspicious" | "dangerous";

interface AutoScanData {
  riskScore: number | null;
  prediction: string;
  reasons: string[];
}

function removeOverlay(): void {
  document.querySelectorAll(`[${OVERLAY_ATTR}]`).forEach(el => el.remove());
}

function renderOverlay(data: AutoScanData, level: WarnLevel): void {
  removeOverlay(); // ensure clean state
  injectOverlayStyles();

  const host = window.location.hostname;
  const score = data.riskScore ?? 0;
  const headline = level === "dangerous"
    ? "Potentially dangerous website"
    : "Suspicious website";
  const iconChar = level === "dangerous" ? "!" : "?";

  // Root wrapper — carries the OVERLAY_ATTR so cosmetic filtering skips it
  const wrapper = document.createElement("div");
  wrapper.setAttribute(OVERLAY_ATTR, level);

  // Panel
  const panel = document.createElement("div");
  panel.className = `sai-panel sai-${level}`;

  // Icon
  const icon = document.createElement("div");
  icon.className = "sai-icon";
  icon.textContent = iconChar;
  icon.setAttribute("aria-hidden", "true");

  // Body
  const body = document.createElement("div");
  body.className = "sai-body";

  const brand = document.createElement("div");
  brand.className = "sai-brand";
  brand.textContent = "SentinelAI Security Warning";

  const headline_el = document.createElement("div");
  headline_el.className = "sai-headline";
  headline_el.textContent = headline;

  const hostEl = document.createElement("div");
  hostEl.className = "sai-host";
  hostEl.textContent = host;
  hostEl.title = host;

  // Score row
  const scoreRow = document.createElement("div");
  scoreRow.className = "sai-score-row";
  const badge = document.createElement("span");
  badge.className = "sai-badge";
  badge.textContent = `Risk score: ${score}/100`;
  const scoreLabel = document.createElement("span");
  scoreLabel.className = "sai-score-label";
  scoreLabel.textContent = level === "dangerous" ? "HIGH RISK" : "SUSPICIOUS";
  scoreRow.append(badge, scoreLabel);

  // Detection reasons (top 3 only — keep overlay compact)
  const topReasons = (data.reasons || []).slice(0, 3);
  let reasonsEl: HTMLDivElement | null = null;
  if (topReasons.length > 0) {
    reasonsEl = document.createElement("div");
    reasonsEl.className = "sai-reasons";
    for (const r of topReasons) {
      const item = document.createElement("div");
      item.className = "sai-reason";
      item.textContent = r;
      reasonsEl.appendChild(item);
    }
  }

  // Action buttons
  const actions = document.createElement("div");
  actions.className = "sai-actions";

  const leaveBtn = document.createElement("button");
  leaveBtn.className = "sai-btn sai-btn-leave";
  leaveBtn.type = "button";
  leaveBtn.id = "sai-leave-site";
  leaveBtn.textContent = "Leave site";
  leaveBtn.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "about:blank";
    }
  });

  const continueBtn = document.createElement("button");
  continueBtn.className = "sai-btn sai-btn-continue";
  continueBtn.type = "button";
  continueBtn.id = "sai-continue-anyway";
  continueBtn.textContent = "Continue anyway";
  continueBtn.addEventListener("click", () => {
    // Dismisses overlay for THIS visit only.
    // Does NOT disable protection, modify allowlist, or trust the domain.
    removeOverlay();
  });

  actions.append(leaveBtn, continueBtn);
  body.append(brand, headline_el, hostEl, scoreRow);
  if (reasonsEl) body.append(reasonsEl);
  body.append(actions);

  // Close (×) button
  const closeBtn = document.createElement("button");
  closeBtn.className = "sai-close";
  closeBtn.type = "button";
  closeBtn.setAttribute("aria-label", "Dismiss warning");
  closeBtn.textContent = "\u00d7"; // ×
  closeBtn.addEventListener("click", () => removeOverlay());

  panel.append(icon, body, closeBtn);
  wrapper.appendChild(panel);

  // Insert at the very start of <body> so it appears above page content
  try {
    document.body.insertBefore(wrapper, document.body.firstChild);
  } catch {
    document.documentElement.appendChild(wrapper);
  }
}

// ---------------------------------------------------------------------------
// Auto-scan core
// ---------------------------------------------------------------------------
function runAutoScan(url: string): void {
  // De-duplicate: only scan each URL once per content-script lifecycle
  if (url === lastScannedUrl) return;
  if (isPrivateOrLocalUrl(url)) return;

  lastScannedUrl = url;

  // Delegate to background.ts — it makes the fetch() call and returns data.
  // Security: background.ts validates sender.id === chrome.runtime.id so the
  // page cannot trigger arbitrary scans via postMessage.
  chrome.runtime.sendMessage({ type: "SCAN_URL", url }, (response) => {
    // Service worker restarting or message channel closed — fail silently
    if (chrome.runtime.lastError) return;
    // Backend unavailable — do NOT show a warning or "safe" state
    if (!response?.ok) return;

    const data: AutoScanData = response.data;
    if (!data || typeof data.riskScore !== "number") return;

    const score = data.riskScore;

    // Safe: score < 35 — do nothing, no UI, no notification
    if (score < RISK_SUSPICIOUS) return;

    // Show overlay
    const level: WarnLevel = score >= RISK_DANGEROUS ? "dangerous" : "suspicious";
    renderOverlay(data, level);
  });
}

// ---------------------------------------------------------------------------
// Navigation detection
// Initial load fires via Promise.resolve().then() (microtask) so the extension
// context is fully initialised before we send the message.
// SPA navigations are tracked via popstate + pushState/replaceState patches.
// ---------------------------------------------------------------------------
let initialScanDone = false;

function triggerScanForCurrentUrl(): void {
  const url = window.location.href;
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;
  runAutoScan(url);
}

// Initial page load
if (!initialScanDone) {
  initialScanDone = true;
  Promise.resolve().then(() => triggerScanForCurrentUrl());
}

// SPA: browser back/forward
window.addEventListener("popstate", () => {
  removeOverlay(); // clear warning from previous route
  triggerScanForCurrentUrl();
});

// SPA: programmatic route changes (React Router, Vue Router, etc.)
(function patchHistoryApi(): void {
  const origPush    = history.pushState.bind(history);
  const origReplace = history.replaceState.bind(history);

  history.pushState = function (...args: Parameters<typeof history.pushState>) {
    origPush(...args);
    removeOverlay();
    triggerScanForCurrentUrl();
  };

  history.replaceState = function (...args: Parameters<typeof history.replaceState>) {
    origReplace(...args);
    // Only re-scan if the URL actually changed (replaceState used for scroll-spy etc.)
    triggerScanForCurrentUrl();
  };
})();