// =============================================================================
// SentinelAI — Background Service Worker
// Handles: DNR ad/tracker blocking, allowlist (network + cosmetic), statistics
// Does NOT touch: phishing detection (popup → FastAPI only)
// =============================================================================

const RULESET_ID = "ad_tracker_rules";
const STORAGE_KEY_ENABLED  = "adBlockingEnabled";
const STORAGE_KEY_ALLOWLIST = "adBlockAllowlist";

// Dynamic allow rules use IDs starting here to avoid collisions with
// static rules (IDs 1–150). MAX_NUMBER_OF_DYNAMIC_RULES is 5000 in Chrome.
const DYNAMIC_RULE_BASE = 10000;

// ---------------------------------------------------------------------------
// Hostname validation & normalisation
// ---------------------------------------------------------------------------

const HOSTNAME_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/**
 * Normalise and validate a raw hostname string (or full URL).
 * Returns the lowercase, www-stripped hostname on success, or null if invalid.
 */
function normaliseHost(raw: string): string | null {
  if (!raw || typeof raw !== "string") return null;

  let host = raw.trim();

  // If it looks like a URL, extract hostname
  if (host.includes("://")) {
    try {
      host = new URL(host).hostname;
    } catch {
      return null;
    }
  } else if (host.includes("/")) {
    // e.g. "example.com/path" — take only hostname part
    host = host.split("/")[0];
  }

  // Strip port
  host = host.replace(/:\d+$/, "");
  // Strip trailing dots
  host = host.replace(/\.+$/, "");
  // Strip www. prefix
  host = host.replace(/^www\./i, "");
  // Lowercase
  host = host.toLowerCase();

  // Support localhost for local testing & demos
  if (host === "localhost") return "localhost";

  // Support IPv4 addresses (e.g. 127.0.0.1 or LAN IP)
  if (IPV4_RE.test(host)) return host;

  // Validate: must look like a real domain (at least one dot, valid chars)
  if (!HOSTNAME_RE.test(host)) return null;

  return host;
}

// ---------------------------------------------------------------------------
// Allowlist storage helpers
// ---------------------------------------------------------------------------

async function getAllowlist(): Promise<string[]> {
  const stored = await chrome.storage.local.get(STORAGE_KEY_ALLOWLIST);
  const list = stored[STORAGE_KEY_ALLOWLIST];
  return Array.isArray(list) ? list.filter(h => typeof h === "string" && h.length > 0) : [];
}

async function saveAllowlist(list: string[]): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY_ALLOWLIST]: list });
}

/**
 * Returns true if 'hostname' is covered by an allowlist entry.
 * "example.com" entry covers "example.com" and "sub.example.com".
 */
function isHostCovered(hostname: string, entry: string): boolean {
  return hostname === entry || hostname.endsWith("." + entry);
}

async function isAllowlisted(rawHostname: string): Promise<boolean> {
  const host = normaliseHost(rawHostname);
  if (!host) return false;
  const list = await getAllowlist();
  return list.some(entry => isHostCovered(host, entry));
}

// ---------------------------------------------------------------------------
// Dynamic DNR rule management
// Allowlisted sites get a dynamic ALLOW rule with priority 2, which beats
// the static block rules at priority 1. The static ruleset is NOT disabled.
// ---------------------------------------------------------------------------

/**
 * Map allowlist entry (hostname) to a stable dynamic rule ID.
 * Uses the hostname's index in the sorted list + DYNAMIC_RULE_BASE.
 * Rebuilds all dynamic rules atomically so IDs are always consistent.
 */
async function rebuildDynamicAllowRules(
  allowlist: string[],
  globallyEnabled: boolean
): Promise<void> {
  // Remove all existing dynamic rules (ours use IDs >= DYNAMIC_RULE_BASE)
  let existingDynamic: chrome.declarativeNetRequest.Rule[] = [];
  try {
    existingDynamic = await chrome.declarativeNetRequest.getDynamicRules();
  } catch (err) {
    console.warn("[SentinelAI] getDynamicRules failed:", err);
  }

  const removeIds = existingDynamic
    .filter(r => r.id >= DYNAMIC_RULE_BASE)
    .map(r => r.id);

  // If protection is globally disabled, just remove all dynamic rules and return.
  // No allow rules needed when the static ruleset is already disabled.
  if (!globallyEnabled || allowlist.length === 0) {
    if (removeIds.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: removeIds,
        addRules: [],
      });
      console.log("[SentinelAI] Removed", removeIds.length, "dynamic allow rules");
    }
    return;
  }

  // Build one allow rule per allowlisted hostname.
  // priority 2 overrides static block rules at priority 1.
  // initiatorDomains: Chrome DNR matches the exact domain and its subdomains.
  const sorted = [...allowlist].sort(); // stable ordering → stable IDs
  const addRules: chrome.declarativeNetRequest.Rule[] = sorted.map((hostname, idx) => ({
    id: DYNAMIC_RULE_BASE + idx,
    priority: 2,
    action: { type: "allow" as const },
    condition: {
      initiatorDomains: [hostname],
      // We want to allow ALL resource types from this initiator
    },
  }));

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: removeIds,
    addRules,
  });

  console.log(
    "[SentinelAI] Dynamic allow rules updated:",
    addRules.length,
    "rules for hosts:",
    sorted
  );
}

// ---------------------------------------------------------------------------
// Allowlist public API
// ---------------------------------------------------------------------------

async function addToAllowlist(rawHostname: string): Promise<{ ok: true; list: string[] } | { ok: false; error: string }> {
  const host = normaliseHost(rawHostname);
  if (!host) return { ok: false, error: "Invalid hostname: " + rawHostname };

  const list = await getAllowlist();
  if (!list.includes(host)) {
    list.push(host);
    await saveAllowlist(list);
  }

  const enabled = await getActualDnrState();
  await rebuildDynamicAllowRules(list, enabled);
  return { ok: true, list };
}

async function removeFromAllowlist(rawHostname: string): Promise<{ ok: true; list: string[] } | { ok: false; error: string }> {
  const host = normaliseHost(rawHostname);
  if (!host) return { ok: false, error: "Invalid hostname: " + rawHostname };

  const updated = (await getAllowlist()).filter(h => h !== host);
  await saveAllowlist(updated);

  const enabled = await getActualDnrState();
  await rebuildDynamicAllowRules(updated, enabled);
  return { ok: true, list: updated };
}

// ---------------------------------------------------------------------------
// DNR static ruleset state
// ---------------------------------------------------------------------------

async function getActualDnrState(): Promise<boolean> {
  try {
    const enabled = await chrome.declarativeNetRequest.getEnabledRulesets();
    return enabled.includes(RULESET_ID);
  } catch (err) {
    console.error("[SentinelAI] getEnabledRulesets failed:", err);
    return false;
  }
}

async function setDnrState(targetEnabled: boolean): Promise<boolean> {
  const before = await chrome.declarativeNetRequest.getEnabledRulesets();
  console.log("[SentinelAI] setDnrState →", targetEnabled, "| before:", before);

  const options: chrome.declarativeNetRequest.UpdateRulesetOptions = {
    enableRulesetIds:  targetEnabled ? [RULESET_ID] : [],
    disableRulesetIds: targetEnabled ? [] : [RULESET_ID],
  };

  await chrome.declarativeNetRequest.updateEnabledRulesets(options);

  const after = await chrome.declarativeNetRequest.getEnabledRulesets();
  const finalState = after.includes(RULESET_ID);
  console.log("[SentinelAI] setDnrState result:", finalState, "| after:", after);

  // Persist state
  await chrome.storage.local.set({ [STORAGE_KEY_ENABLED]: finalState });

  // Sync dynamic allow rules: only active when protection is ON
  const list = await getAllowlist();
  await rebuildDynamicAllowRules(list, finalState);

  return finalState;
}

// ---------------------------------------------------------------------------
// Statistics via declarativeNetRequestFeedback
// getMatchedRules() is tab-scoped and resets per navigation.
// We return null if unavailable rather than fabricating a count.
// ---------------------------------------------------------------------------

async function getMatchedRuleCount(tabId: number | null): Promise<number | null> {
  if (typeof chrome.declarativeNetRequest.getMatchedRules !== "function") {
    return null;
  }
  try {
    const filter = (tabId !== null && tabId >= 0)
      ? { tabId, minTimeStamp: 0 }
      : undefined;
    const result = await chrome.declarativeNetRequest.getMatchedRules(filter);
    return result.rulesMatchedInfo.length;
  } catch (err) {
    console.warn("[SentinelAI] getMatchedRules failed:", err);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Startup initialisation
// ---------------------------------------------------------------------------

async function initDnrProtection(): Promise<void> {
  try {
    const stored = await chrome.storage.local.get(STORAGE_KEY_ENABLED);
    const saved = stored[STORAGE_KEY_ENABLED];
    const target = typeof saved === "boolean" ? saved : true; // default ON
    await setDnrState(target);
  } catch (err) {
    console.error("[SentinelAI] init error:", err);
  }
}

chrome.runtime.onInstalled.addListener(() => { initDnrProtection(); });
chrome.runtime.onStartup.addListener(() => { initDnrProtection(); });
initDnrProtection();

// ---------------------------------------------------------------------------
// Message handler — top-level synchronous registration (required for MV3)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {

  // ── GET DNR state ──────────────────────────────────────────────────────────
  if (message?.type === "GET_AD_BLOCKING_STATE") {
    getActualDnrState()
      .then(enabled => { sendResponse({ ok: true, enabled }); })
      .catch(err => { sendResponse({ ok: false, error: String(err) }); });
    return true;
  }

  // ── SET DNR state ──────────────────────────────────────────────────────────
  if (message?.type === "SET_AD_BLOCKING_STATE" && typeof message.enabled === "boolean") {
    const currentState = getActualDnrState();
    currentState
      .then(async (prev) => {
        try {
          const finalEnabled = await setDnrState(message.enabled);
          sendResponse({ ok: true, enabled: finalEnabled });
        } catch (error: unknown) {
          const msg = error instanceof Error ? error.message : String(error);
          sendResponse({ ok: false, enabled: prev, error: msg });
        }
      })
      .catch(err => { sendResponse({ ok: false, error: String(err) }); });
    return true;
  }

  // ── GET allowlist ─────────────────────────────────────────────────────────
  if (message?.type === "GET_ALLOWLIST") {
    getAllowlist()
      .then(list => { sendResponse({ ok: true, list }); })
      .catch(err => { sendResponse({ ok: false, error: String(err) }); });
    return true;
  }

  // ── CHECK allowlist for hostname ──────────────────────────────────────────
  if (message?.type === "CHECK_ALLOWLIST" && typeof message.hostname === "string") {
    isAllowlisted(message.hostname)
      .then(allowed => { sendResponse({ ok: true, allowed }); })
      .catch(err => { sendResponse({ ok: false, error: String(err) }); });
    return true;
  }

  // ── ADD to allowlist ──────────────────────────────────────────────────────
  if (message?.type === "ADD_ALLOWLIST" && typeof message.hostname === "string") {
    addToAllowlist(message.hostname)
      .then(result => { sendResponse(result); })
      .catch(err => { sendResponse({ ok: false, error: String(err) }); });
    return true;
  }

  // ── REMOVE from allowlist ─────────────────────────────────────────────────
  if (message?.type === "REMOVE_ALLOWLIST" && typeof message.hostname === "string") {
    removeFromAllowlist(message.hostname)
      .then(result => { sendResponse(result); })
      .catch(err => { sendResponse({ ok: false, error: String(err) }); });
    return true;
  }

  // ── GET matched rule count ────────────────────────────────────────────────
  if (message?.type === "GET_MATCHED_COUNT") {
    const tabId = typeof message.tabId === "number" ? message.tabId : null;
    getMatchedRuleCount(tabId)
      .then(count => { sendResponse({ ok: true, count }); })
      .catch(() => { sendResponse({ ok: true, count: null }); });
    return true;
  }

  // ── AUTO PHISHING SCAN ────────────────────────────────────────────────────
  // Accepts: { type: "SCAN_URL", url: string }
  // Only honour requests that originate from the extension's own content
  // scripts (sender.id === chrome.runtime.id and the tab actually exists).
  // The page itself cannot call this via postMessage.
  if (message?.type === "SCAN_URL" && typeof message.url === "string") {
    // Validate sender — must be our own extension running in a real tab
    if (
      _sender.id !== chrome.runtime.id ||
      typeof _sender.tab?.id !== "number"
    ) {
      sendResponse({ ok: false, error: "Unauthorized sender" });
      return true;
    }

    const urlToScan = message.url;

    // Only allow http / https URLs
    let parsed: URL;
    try {
      parsed = new URL(urlToScan);
    } catch {
      sendResponse({ ok: false, error: "Invalid URL" });
      return true;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      sendResponse({ ok: false, error: "Non-HTTP URL" });
      return true;
    }

    // Fetch from the local FastAPI backend.
    // On ANY failure → respond { ok: false } — do NOT fabricate a safe result.
    fetch("http://127.0.0.1:8000/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlToScan }),
      signal: AbortSignal.timeout(10_000), // 10 s hard limit
    })
      .then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json() as {
          riskScore: number | null;
          prediction: string;
          reasons: string[];
        };
        sendResponse({ ok: true, data });
      })
      .catch((err) => {
        console.warn("[SentinelAI] Auto-scan failed (silent):", err?.message ?? err);
        sendResponse({ ok: false, error: "backend_unavailable" });
      });

    return true; // keep channel open for async response
  }

  return false;
});
