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

// Pre-build combined selector string for efficient querySelectorAll
const COMBINED_SELECTOR = AD_SELECTORS.join(",");
const HIDDEN_ATTR = "data-sentinel-hidden";

// ---------------------------------------------------------------------------
// State
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
// Entry point
// ---------------------------------------------------------------------------
checkAndStart();