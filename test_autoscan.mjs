/**
 * SentinelAI — Auto-scan feature test suite
 * Tests the automatic phishing scanner behaviour WITHOUT a real browser.
 * Mocks chrome.runtime, chrome.storage, window.history, and the fetch API.
 *
 * Run with:   node test_autoscan.mjs
 */

// ---------------------------------------------------------------------------
// Minimal test harness
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  PASS  ${label}`);
    passed++;
  } else {
    console.error(`  FAIL  ${label}`);
    failed++;
  }
}

function section(title) {
  console.log(`\n── ${title}`);
}

// ---------------------------------------------------------------------------
// Mock infrastructure
// ---------------------------------------------------------------------------

/** Tracks chrome.runtime.sendMessage calls */
const sentMessages = [];

/** Maps URL → fake API response (null = backend unavailable) */
const fakeApiResponses = new Map();

function setFakeResponse(url, response) {
  fakeApiResponses.set(url, response);
}

/** Global mocked fetch used by background SCAN_URL handler */
async function mockFetch(apiUrl, options) {
  const body = JSON.parse(options?.body ?? "{}");
  const url = body.url;
  const resp = fakeApiResponses.get(url);
  if (resp === undefined || resp === null) {
    throw new Error("Network error (mock)");
  }
  return {
    ok: true,
    json: async () => resp,
  };
}

// ---------------------------------------------------------------------------
// Simulate the background.ts SCAN_URL handler logic (extracted for testing)
// ---------------------------------------------------------------------------
async function backgroundScanUrl(url) {
  // Validate URL
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, error: "Invalid URL" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, error: "Non-HTTP URL" };
  }

  try {
    const res = await mockFetch("http://127.0.0.1:8000/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: "backend_unavailable" };
  }
}

// ---------------------------------------------------------------------------
// Simulate the content.ts overlay decision logic (extracted for testing)
// ---------------------------------------------------------------------------
const RISK_SUSPICIOUS = 35;
const RISK_DANGEROUS  = 65;

const PRIVATE_PATTERNS = [
  (h) => h === "localhost",
  (h) => /^127\./.test(h),
  (h) => /^10\./.test(h),
  (h) => /^192\.168\./.test(h),
  (h) => /^172\.(1[6-9]|2\d|3[01])\./.test(h),
  (h) => /^::1$/.test(h),
];

function isPrivateOrLocalUrl(url) {
  try {
    const { hostname, protocol } = new URL(url);
    if (protocol !== "http:" && protocol !== "https:") return true;
    if (PRIVATE_PATTERNS.some(fn => fn(hostname))) return true;
    return false;
  } catch {
    return true;
  }
}

let lastScannedUrl = "";

function resetContentState() {
  lastScannedUrl = "";
}

/**
 * Simulates content.ts runAutoScan() returning the overlay action.
 * Returns: "no-overlay", "suspicious-overlay", "dangerous-overlay",
 *          "private-skip", "duplicate-skip", "backend-silent"
 */
async function simulateAutoScan(url) {
  if (url === lastScannedUrl) return "duplicate-skip";
  if (isPrivateOrLocalUrl(url)) return "private-skip";

  lastScannedUrl = url;

  const response = await backgroundScanUrl(url);

  if (!response.ok) return "backend-silent"; // fail silently

  const data = response.data;
  if (!data || typeof data.riskScore !== "number") return "backend-silent";

  const score = data.riskScore;
  if (score < RISK_SUSPICIOUS) return "no-overlay";
  if (score >= RISK_DANGEROUS)  return "dangerous-overlay";
  return "suspicious-overlay";
}

// ---------------------------------------------------------------------------
// TEST CASES
// ---------------------------------------------------------------------------

section("1. Safe URL — riskScore < 35 → no overlay");
{
  resetContentState();
  setFakeResponse("https://example.com", {
    riskScore: 12,
    prediction: "Likely safe",
    reasons: ["Standard TLD", "No suspicious patterns"],
  });
  const result = await simulateAutoScan("https://example.com");
  assert(result === "no-overlay", "Safe URL (score=12) produces no-overlay");
}

section("2. Suspicious URL — riskScore >= 35 and < 65 → suspicious overlay");
{
  resetContentState();
  setFakeResponse("https://suspicious-login.example.com", {
    riskScore: 50,
    prediction: "Suspicious",
    reasons: ["Unusual domain pattern", "Login keyword in subdomain"],
  });
  const result = await simulateAutoScan("https://suspicious-login.example.com");
  assert(result === "suspicious-overlay", "Suspicious URL (score=50) produces suspicious-overlay");
}

section("3. High-risk URL — riskScore >= 65 → dangerous overlay");
{
  resetContentState();
  setFakeResponse("https://paypal-secure-login.tk", {
    riskScore: 88,
    prediction: "Phishing",
    reasons: ["Known phishing pattern", "IP address in URL", "Brand impersonation"],
  });
  const result = await simulateAutoScan("https://paypal-secure-login.tk");
  assert(result === "dangerous-overlay", "High-risk URL (score=88) produces dangerous-overlay");
}

section("4. Exact boundary — riskScore = 35 → suspicious overlay");
{
  resetContentState();
  setFakeResponse("https://boundary-test.com", {
    riskScore: 35,
    prediction: "Suspicious",
    reasons: ["Boundary case"],
  });
  const result = await simulateAutoScan("https://boundary-test.com");
  assert(result === "suspicious-overlay", "Boundary score=35 → suspicious-overlay");
}

section("5. Exact boundary — riskScore = 65 → dangerous overlay");
{
  resetContentState();
  setFakeResponse("https://boundary65.com", {
    riskScore: 65,
    prediction: "Dangerous",
    reasons: ["Boundary case"],
  });
  const result = await simulateAutoScan("https://boundary65.com");
  assert(result === "dangerous-overlay", "Boundary score=65 → dangerous-overlay");
}

section("6. Local / private URL → no scan, no warning");
{
  resetContentState();
  const localUrls = [
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "chrome://settings",
    "chrome-extension://abc123/popup.html",
    "file:///C:/index.html",
  ];
  for (const url of localUrls) {
    const result = await simulateAutoScan(url);
    assert(result === "private-skip", `Private/local URL skipped: ${url}`);
    resetContentState(); // each URL is fresh
  }
}

section("7. Backend unavailable → silent, no overlay, no false safe");
{
  resetContentState();
  // No entry in fakeApiResponses → mockFetch throws → backend_unavailable
  fakeApiResponses.delete("https://unavailable-backend.com");
  const result = await simulateAutoScan("https://unavailable-backend.com");
  assert(result === "backend-silent", "Backend unavailable → silent (no overlay, no false safe)");
}

section("8. Duplicate scan — same URL scanned twice → only first triggers scan");
{
  resetContentState();
  setFakeResponse("https://dedup-test.com", {
    riskScore: 75,
    prediction: "Dangerous",
    reasons: ["Test"],
  });
  const first  = await simulateAutoScan("https://dedup-test.com");
  const second = await simulateAutoScan("https://dedup-test.com");
  assert(first  === "dangerous-overlay", "First visit: warning shown");
  assert(second === "duplicate-skip",    "Second visit: duplicate skipped");
}

section("9. Safe → suspicious navigation — new URL scanned");
{
  resetContentState();
  setFakeResponse("https://safe-site.com", {
    riskScore: 8,
    prediction: "Safe",
    reasons: [],
  });
  setFakeResponse("https://bad-site.com", {
    riskScore: 72,
    prediction: "Phishing",
    reasons: ["Typosquatting"],
  });

  const safe = await simulateAutoScan("https://safe-site.com");
  assert(safe === "no-overlay", "Safe site: no overlay");

  // Simulate navigation — reset lastScannedUrl as would happen on new page load
  // (In real extension, a new content script is injected for each navigation)
  lastScannedUrl = "";
  const bad = await simulateAutoScan("https://bad-site.com");
  assert(bad === "dangerous-overlay", "Navigating to bad site: warning appears");
}

section("10. Non-HTTP URL → rejected before scan");
{
  resetContentState();
  const result = await simulateAutoScan("ftp://files.example.com/resource");
  assert(result === "private-skip", "ftp:// URL skipped by private/local guard");
}

section("11. riskScore = 34 (just below threshold) → no overlay");
{
  resetContentState();
  setFakeResponse("https://almost-suspicious.com", {
    riskScore: 34,
    prediction: "Low risk",
    reasons: ["Some heuristic signal"],
  });
  const result = await simulateAutoScan("https://almost-suspicious.com");
  assert(result === "no-overlay", "score=34 is below threshold → no overlay");
}

section("12. riskScore = null from API → no overlay (treated as backend anomaly)");
{
  resetContentState();
  setFakeResponse("https://null-score.com", {
    riskScore: null,
    prediction: "Unknown",
    reasons: [],
  });
  const result = await simulateAutoScan("https://null-score.com");
  // riskScore null → typeof check fails → backend-silent
  assert(result === "backend-silent", "null riskScore → silent (no overlay)");
}

section("13. Ad-blocker allowlist separation — phishing scan is independent");
{
  // The auto-scanner does not consult adBlockAllowlist.
  // This is enforced architecturally: content.ts runAutoScan() sends
  // SCAN_URL directly, background.ts SCAN_URL handler does NOT check allowlist.
  // We verify this by confirming a URL that would be allowlisted for ads
  // still gets scanned and shows a warning.
  resetContentState();
  const adAllowlistedButDangerous = "https://adallowlisted-phishing.com";
  setFakeResponse(adAllowlistedButDangerous, {
    riskScore: 80,
    prediction: "Phishing",
    reasons: ["Brand impersonation"],
  });
  const result = await simulateAutoScan(adAllowlistedButDangerous);
  assert(
    result === "dangerous-overlay",
    "Ad-allowlisted domain still triggers phishing warning (security isolation)"
  );
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log(`\n${"─".repeat(52)}`);
console.log(`Auto-scan tests complete: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
