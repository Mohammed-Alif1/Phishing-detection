type ScanResult = {
  riskScore: number | null;
  modelScore: number | null;
  heuristicScore: number;
  prediction: string;
  reasons: string[];
  url: string;
  localAddress?: boolean;
};

const $ = (id: string) => document.getElementById(id);
const websiteEl = $("website");
const titleEl = $("title");
const statusEl = $("status");
const fullUrlEl = $("fullUrl");
const urlInput = $("urlInput") as HTMLInputElement | null;
const scanBtn = $("scanBtn") as HTMLButtonElement | null;
const scanButtonText = $("scanButtonText");
const riskScoreEl = $("riskScore");
const predictionEl = $("prediction");
const riskMeter = $("riskMeter");
const riskRing = $("scoreRing");
const assessmentCard = $("assessmentCard");
const reasonsEl = $("reasons");
const signalCount = $("signalCount");
const engineState = $("engineState");

let currentUrl = "";
let currentTitle = "";
let currentTabId: number | null = null;

function setStatus(message: string, tone: "good" | "warn" | "bad" = "good") {
  if (!statusEl) return;
  statusEl.replaceChildren();
  const dot = document.createElement("span");
  dot.className = "status-dot";
  dot.style.background = tone === "bad" ? "#ff647c" : tone === "warn" ? "#ffc66e" : "#4be0c1";
  statusEl.append(dot, document.createTextNode(message));
}

function renderReasons(reasons: string[]) {
  if (!reasonsEl || !signalCount) return;
  reasonsEl.replaceChildren();
  signalCount.textContent = `${reasons.length} signal${reasons.length === 1 ? "" : "s"}`;

  if (!reasons.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No specific URL warning signals were returned. This does not prove the site is safe.";
    reasonsEl.append(empty);
    return;
  }

  for (const reason of reasons) {
    const isBad = /impersonat|phishing|credential|IP address|@ symbol|punycode|high-risk|known malicious/i.test(reason);
    const isWarn = /unusual|multiple|long|keyword|non-standard|shortener|HTTPS|review|local/i.test(reason);
    const item = document.createElement("div");
    item.className = `signal-item ${isBad ? "bad" : isWarn ? "warn" : "good"}`;
    const icon = document.createElement("span");
    icon.className = "signal-icon";
    icon.textContent = isBad ? "!" : isWarn ? "•" : "✓";
    const copy = document.createElement("div");
    copy.className = "signal-copy";
    const strong = document.createElement("strong");
    strong.textContent = isBad ? "High-priority indicator" : isWarn ? "Review recommended" : "URL check";
    const detail = document.createElement("p");
    detail.textContent = reason;
    copy.append(strong, detail);
    item.append(icon, copy);
    reasonsEl.append(item);
  }
}

function renderResult(data: ScanResult) {
  if (riskScoreEl) riskScoreEl.textContent = data.riskScore === null ? "—" : String(data.riskScore);
  if (predictionEl) predictionEl.textContent = data.prediction;
  if (assessmentCard) {
    const risk = data.riskScore ?? 0;
    assessmentCard.classList.remove("low", "medium", "high");
    assessmentCard.classList.add(data.riskScore === null ? "medium" : risk >= 65 ? "high" : risk >= 35 ? "medium" : "low");
  }
  if (riskMeter) riskMeter.style.width = `${data.riskScore ?? 0}%`;
  if (riskRing) riskRing.setAttribute("aria-label", data.riskScore === null ? "Risk score unavailable" : `Risk score ${data.riskScore} out of 100`);
  renderReasons(data.reasons || []);
  if (engineState) engineState.textContent = "API connected";
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  currentTabId = tab?.id ?? null;

  if (!tab?.url) {
    if (websiteEl) websiteEl.textContent = "Unavailable";
    if (titleEl) titleEl.textContent = "No active page detected";
    if (fullUrlEl) fullUrlEl.textContent = "Open a website and try again.";
    setStatus("No active tab URL", "warn");
    // Still init ad blocker UI even without a tab URL
    fetchAdBlockState();
    fetchStats(null);
    return;
  }

  currentUrl = tab.url;
  currentTitle = tab.title || "Untitled page";
  try {
    const parsed = new URL(tab.url);
    if (websiteEl) websiteEl.textContent = parsed.hostname || parsed.protocol.replace(":", "");
    // Populate hostname for allowlist (HTTP/HTTPS tabs only)
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      currentHostname = parsed.hostname.replace(/^www\./, "");
    }
  } catch {
    if (websiteEl) websiteEl.textContent = "Browser internal page";
  }
  if (titleEl) titleEl.textContent = currentTitle;
  if (fullUrlEl) fullUrlEl.textContent = currentUrl;
  if (urlInput) urlInput.value = currentUrl;
  setStatus("Ready to scan");

  // Initialise ad blocker section with real tab context
  fetchAdBlockState();
  if (currentHostname && allowlistBtn) {
    allowlistBtn.style.display = "";
    fetchAllowlistState();
  }
  fetchStats(currentTabId);
});

scanBtn?.addEventListener("click", async () => {
  const urlToScan = (urlInput?.value || currentUrl).trim();
  if (!urlToScan) {
    setStatus("Enter a URL to scan", "warn");
    return;
  }
  let parsed: URL;
  try {
    parsed = new URL(urlToScan);
  } catch {
    setStatus("Invalid page URL", "bad");
    return;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    setStatus("Only HTTP and HTTPS URLs can be scanned", "warn");
    if (predictionEl) predictionEl.textContent = "Not scannable";
    renderReasons(["Open a normal HTTP or HTTPS website to run URL analysis."]);
    if (riskScoreEl) riskScoreEl.textContent = "—";
    if (riskMeter) riskMeter.style.width = "0%";
    return;
  }

  if (scanBtn) scanBtn.disabled = true;
  if (scanButtonText) scanButtonText.textContent = "Analysing URL…";
  setStatus("Running local analysis");
  if (engineState) engineState.textContent = "Connecting…";

  try {
    const response = await fetch("http://127.0.0.1:8000/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlToScan }),
    });
    if (!response.ok) throw new Error(`API returned HTTP ${response.status}`);
    const data = (await response.json()) as ScanResult;
    renderResult(data);
    setStatus("Analysis complete");
  } catch (error) {
    console.error("SentinelAI scan failed:", error);
    setStatus("Local API unavailable", "bad");
    if (engineState) engineState.textContent = "API disconnected";
    if (predictionEl) predictionEl.textContent = "Scan unavailable";
    renderReasons(["Start the FastAPI backend at 127.0.0.1:8000 and scan again."]);
  } finally {
    if (scanBtn) scanBtn.disabled = false;
    if (scanButtonText) scanButtonText.textContent = "Run security scan";
  }
});


// =============================================================================
// AD & TRACKER PROTECTION section
// =============================================================================

const RULESET_ID = "ad_tracker_rules";

const adblockToggle = $("adblockToggle") as HTMLInputElement | null;
const adblockStatus = $("adblockStatus");
const adblockTitle = $("adblockTitle");
const adblockStat = $("adblockStat");
const allowlistBtn = $("allowlistBtn") as HTMLButtonElement | null;
const allowlistStatus = $("allowlistStatus");

// Current site hostname (populated after tabs.query)
let currentHostname = "";

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

function updateAdBlockUI(enabled: boolean): void {
  if (adblockToggle) {
    adblockToggle.checked = enabled;
    adblockToggle.disabled = false;
  }
  if (adblockTitle) {
    adblockTitle.textContent = "Ad & Tracker Protection";
  }
  if (adblockStatus) {
    adblockStatus.textContent = enabled
      ? "Network blocking active"
      : "Protection disabled";
  }
}

function showAdBlockError(message: string): void {
  if (adblockToggle) adblockToggle.disabled = false;
  if (adblockStatus) adblockStatus.textContent = message;
}

// ---------------------------------------------------------------------------
// Statistics — honest: use getMatchedRules if available, else text fallback
// ---------------------------------------------------------------------------

function fetchStats(tabId: number | null): void {
  if (!adblockStat) return;
  chrome.runtime.sendMessage({ type: "GET_MATCHED_COUNT", tabId }, (response) => {
    if (chrome.runtime.lastError || !response?.ok) {
      adblockStat.textContent = "Blocking active";
      return;
    }
    const count = response.count;
    if (typeof count === "number") {
      adblockStat.textContent = count === 0
        ? "No requests blocked on this page yet"
        : `${count} request${count === 1 ? "" : "s"} blocked this page load`;
    } else {
      adblockStat.textContent = "Blocking active";
    }
  });
}

// ---------------------------------------------------------------------------
// DNR state fetch
// ---------------------------------------------------------------------------

function fetchAdBlockState(): void {
  if (adblockStatus) adblockStatus.textContent = "Loading protection status…";
  if (adblockToggle) adblockToggle.disabled = true;

  chrome.runtime.sendMessage({ type: "GET_AD_BLOCKING_STATE" }, (response) => {
    if (chrome.runtime.lastError) {
      // Fallback: query DNR directly if service worker was cold-starting
      if (chrome?.declarativeNetRequest?.getEnabledRulesets) {
        chrome.declarativeNetRequest.getEnabledRulesets()
          .then((rulesets) => { updateAdBlockUI(rulesets.includes(RULESET_ID)); })
          .catch(() => { showAdBlockError("Protection status unavailable"); });
        return;
      }
      showAdBlockError("Protection status unavailable");
      return;
    }
    if (response?.ok && typeof response.enabled === "boolean") {
      updateAdBlockUI(response.enabled);
    } else {
      showAdBlockError(response?.error || "Protection status unavailable");
    }
  });
}

// ---------------------------------------------------------------------------
// Allowlist UI
// ---------------------------------------------------------------------------

function renderAllowlistBtn(allowed: boolean): void {
  if (!allowlistBtn) return;
  allowlistBtn.textContent = allowed ? "Remove from allowlist" : "Allow this site";
  allowlistBtn.dataset.allowed = allowed ? "1" : "0";
  if (allowlistStatus) {
    allowlistStatus.textContent = allowed
      ? `${currentHostname} is allowlisted — blocking paused`
      : "";
  }
}

function fetchAllowlistState(): void {
  if (!currentHostname) return;
  chrome.runtime.sendMessage(
    { type: "CHECK_ALLOWLIST", hostname: currentHostname },
    (response) => {
      if (chrome.runtime.lastError || !response?.ok) return;
      renderAllowlistBtn(response.allowed === true);
    }
  );
}

if (allowlistBtn) {
  allowlistBtn.addEventListener("click", () => {
    if (!currentHostname) return;
    const isCurrentlyAllowed = allowlistBtn.dataset.allowed === "1";
    const msgType = isCurrentlyAllowed ? "REMOVE_ALLOWLIST" : "ADD_ALLOWLIST";
    allowlistBtn.disabled = true;
    chrome.runtime.sendMessage(
      { type: msgType, hostname: currentHostname },
      (response) => {
        allowlistBtn.disabled = false;
        if (chrome.runtime.lastError || !response?.ok) return;
        renderAllowlistBtn(!isCurrentlyAllowed);
      }
    );
  });
}

// ---------------------------------------------------------------------------
// Toggle listener
// ---------------------------------------------------------------------------

if (adblockToggle) {
  // fetchAdBlockState() is called from within the tabs.query callback above.

  adblockToggle.addEventListener("change", () => {
    const desired = adblockToggle.checked;
    const previous = !desired;

    adblockToggle.disabled = true;
    if (adblockStatus) adblockStatus.textContent = "Updating protection…";

    chrome.runtime.sendMessage(
      { type: "SET_AD_BLOCKING_STATE", enabled: desired },
      (response) => {
        adblockToggle.disabled = false;
        if (chrome.runtime.lastError) {
          const errMsg = chrome.runtime.lastError.message || "runtime.lastError";
          adblockToggle.checked = previous;
          showAdBlockError(`Error: ${errMsg}`);
          return;
        }
        if (response?.ok && typeof response.enabled === "boolean") {
          updateAdBlockUI(response.enabled);
        } else {
          adblockToggle.checked = previous;
          showAdBlockError(response?.error || "Unknown error");
        }
      }
    );
  });
}

// (ad blocker init is driven from the tabs.query callback above)

// ---------------------------------------------------------------------------
// Backend connectivity check
// ---------------------------------------------------------------------------

fetch("http://127.0.0.1:8000/", { method: "GET" })
  .then((res) => {
    if (res.ok && engineState) engineState.textContent = "API connected";
  })
  .catch(() => {
    if (engineState) engineState.textContent = "API disconnected";
  });

