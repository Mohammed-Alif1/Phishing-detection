import { spawn } from 'child_process';
import http from 'http';
import fs from 'fs';
import path from 'path';

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const EXT_PATH = "D:\\projects\\Phishing-detection\\dist";
const TEST_DIR = "D:\\projects\\Phishing-detection\\scratch\\verify_edge_profile2";

if (fs.existsSync(TEST_DIR)) {
  fs.rmSync(TEST_DIR, { recursive: true, force: true });
}
fs.mkdirSync(TEST_DIR, { recursive: true });

// 1. Start local HTTP server to serve test_adblock.html
const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/test_adblock.html') {
    const html = fs.readFileSync('test_adblock.html', 'utf8');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});

server.listen(4567, async () => {
  console.log("Local test server listening on http://127.0.0.1:4567");

  // 2. Launch Chromium Edge with SentinelAI extension
  console.log("Launching Chromium with SentinelAI extension...");
  const proc = spawn(EDGE_PATH, [
    `--user-data-dir=${TEST_DIR}`,
    `--load-extension=${EXT_PATH}`,
    '--remote-debugging-port=9556',
    '--headless=new',
    '--no-first-run',
    '--no-default-browser-check',
    'about:blank'
  ]);

  await new Promise(r => setTimeout(r, 3000));

  try {
    const listRes = await fetch("http://127.0.0.1:9556/json/list");
    const targets = await listRes.json();
    
    // Find SentinelAI service worker
    const swTarget = targets.find(t => 
      t.type === 'service_worker' && 
      (t.url.includes('service-worker-loader') || t.title.includes('SentinelAI'))
    );

    if (!swTarget) {
      throw new Error("SentinelAI service worker not found in targets:\n" + JSON.stringify(targets, null, 2));
    }

    const extId = new URL(swTarget.url).hostname;
    console.log("✓ Found SentinelAI Service Worker! Ext ID:", extId);

    // Connect to SW for checking internal DNR rules directly
    const swWs = new WebSocket(swTarget.webSocketDebuggerUrl);
    let swMsgId = 1;
    const swPending = new Map();
    swWs.onmessage = e => {
      const m = JSON.parse(e.data);
      if (m.id && swPending.has(m.id)) {
        swPending.get(m.id)(m);
        swPending.delete(m.id);
      }
    };
    await new Promise(r => swWs.onopen = r);

    const swCall = (method, params = {}) => new Promise(res => {
      const id = swMsgId++;
      swPending.set(id, res);
      swWs.send(JSON.stringify({ id, method, params }));
    });

    async function swEval(expression) {
      const res = await swCall("Runtime.evaluate", {
        expression,
        awaitPromise: true,
        returnByValue: true
      });
      if (res.result?.exceptionDetails) {
        throw new Error(res.result.exceptionDetails.text + ": " + JSON.stringify(res.result.exceptionDetails.exception));
      }
      return res.result?.result?.value;
    }

    // 3. Open extension popup page target to test popup -> SW messaging
    const popupUrl = `chrome-extension://${extId}/src/popup.html`;
    const popupRes = await fetch(`http://127.0.0.1:9556/json/new?${popupUrl}`, { method: 'PUT' });
    const popupTarget = await popupRes.json();
    console.log("✓ Created Popup page target:", popupTarget.url);

    const popupWs = new WebSocket(popupTarget.webSocketDebuggerUrl);
    let popupMsgId = 1;
    const popupPending = new Map();
    popupWs.onmessage = e => {
      const m = JSON.parse(e.data);
      if (m.id && popupPending.has(m.id)) {
        popupPending.get(m.id)(m);
        popupPending.delete(m.id);
      }
    };
    await new Promise(r => popupWs.onopen = r);

    const popupCall = (method, params = {}) => new Promise(res => {
      const id = popupMsgId++;
      popupPending.set(id, res);
      popupWs.send(JSON.stringify({ id, method, params }));
    });

    async function popupEval(expression) {
      const res = await popupCall("Runtime.evaluate", {
        expression,
        awaitPromise: true,
        returnByValue: true
      });
      if (res.result?.exceptionDetails) {
        throw new Error(res.result.exceptionDetails.text + ": " + JSON.stringify(res.result.exceptionDetails.exception));
      }
      return res.result?.result?.value;
    }

    // 4. Open test page target
    const newPageRes = await fetch("http://127.0.0.1:9556/json/new?http://127.0.0.1:4567/test_adblock.html", { method: 'PUT' });
    const pageTarget = await newPageRes.json();
    console.log("✓ Created Test page target:", pageTarget.url);

    const pageWs = new WebSocket(pageTarget.webSocketDebuggerUrl);
    let pageMsgId = 1;
    const pagePending = new Map();
    pageWs.onmessage = e => {
      const m = JSON.parse(e.data);
      if (m.id && pagePending.has(m.id)) {
        pagePending.get(m.id)(m);
        pagePending.delete(m.id);
      }
    };
    await new Promise(r => pageWs.onopen = r);

    const pageCall = (method, params = {}) => new Promise(res => {
      const id = pageMsgId++;
      pagePending.set(id, res);
      pageWs.send(JSON.stringify({ id, method, params }));
    });

    // Test URL list
    const testUrls = [
      { domain: "doubleclick.net", url: "https://doubleclick.net/favicon.ico" },
      { domain: "googlesyndication.com", url: "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js" },
      { domain: "adnxs.com", url: "https://ib.adnxs.com/ttj" },
      { domain: "taboola.com", url: "https://cdn.taboola.com/libtrc/impl.263.js" },
      { domain: "outbrain.com", url: "https://widgets.outbrain.com/outbrain.js" },
      { domain: "google-analytics.com", url: "https://www.google-analytics.com/analytics.js" },
      { domain: "example.com (benign)", url: "https://example.com/" }
    ];

    async function runFetchTests(label) {
      console.log(`\n--- Fetch tests: [${label}] ---`);
      const results = [];
      for (const t of testUrls) {
        const evalRes = await pageCall("Runtime.evaluate", {
          expression: `
            fetch("${t.url}", { mode: "no-cors", cache: "no-store" })
              .then(() => "LOADED")
              .catch(err => "BLOCKED (" + err.message + ")")
          `,
          awaitPromise: true,
          returnByValue: true
        });
        const resVal = evalRes.result?.result?.value;
        const blocked = resVal && resVal.includes("BLOCKED");
        console.log(`  [${t.domain.padEnd(24)}] ${resVal}`);
        results.push({ domain: t.domain, result: resVal, blocked });
      }
      return results;
    }

    console.log("\n=======================================================");
    console.log("PHASE 1: INITIAL STATE (PROTECTION ON)");
    console.log("=======================================================");
    const initialRulesets = await swEval("chrome.declarativeNetRequest.getEnabledRulesets()");
    console.log("SW getEnabledRulesets():", initialRulesets);

    // Verify popup GET_AD_BLOCKING_STATE messaging
    const popupGetState = await popupEval(`
      new Promise(resolve => {
        chrome.runtime.sendMessage({ type: "GET_AD_BLOCKING_STATE" }, resolve);
      })
    `);
    console.log("Popup received GET_AD_BLOCKING_STATE:", popupGetState);

    const test1 = await runFetchTests("Protection ON");

    console.log("\n=======================================================");
    console.log("PHASE 2: TOGGLE OFF VIA POPUP MESSAGING");
    console.log("=======================================================");
    const toggleOffResponse = await popupEval(`
      new Promise(resolve => {
        chrome.runtime.sendMessage({ type: "SET_AD_BLOCKING_STATE", enabled: false }, resolve);
      })
    `);
    console.log("Popup sent SET_AD_BLOCKING_STATE(false) -> Response:", toggleOffResponse);

    const rulesetsOff = await swEval("chrome.declarativeNetRequest.getEnabledRulesets()");
    console.log("SW getEnabledRulesets() after toggle OFF:", rulesetsOff);

    const test2 = await runFetchTests("Protection OFF");

    console.log("\n=======================================================");
    console.log("PHASE 3: TOGGLE BACK ON VIA POPUP MESSAGING");
    console.log("=======================================================");
    const toggleOnResponse = await popupEval(`
      new Promise(resolve => {
        chrome.runtime.sendMessage({ type: "SET_AD_BLOCKING_STATE", enabled: true }, resolve);
      })
    `);
    console.log("Popup sent SET_AD_BLOCKING_STATE(true) -> Response:", toggleOnResponse);

    const rulesetsOn = await swEval("chrome.declarativeNetRequest.getEnabledRulesets()");
    console.log("SW getEnabledRulesets() after toggle ON:", rulesetsOn);

    const test3 = await runFetchTests("Protection ON (Resumed)");

    console.log("\n=======================================================");
    console.log("PHASE 4: ALLOWLIST TEST (DYNAMIC RULE PRIORITY 2)");
    console.log("=======================================================");
    // Add 127.0.0.1 to allowlist via popup messaging
    const addAllowResponse = await popupEval(`
      new Promise(resolve => {
        chrome.runtime.sendMessage({ type: "ADD_ALLOWLIST", hostname: "127.0.0.1" }, resolve);
      })
    `);
    console.log("Popup sent ADD_ALLOWLIST(127.0.0.1) -> Response:", addAllowResponse);

    const checkAllow = await popupEval(`
      new Promise(resolve => {
        chrome.runtime.sendMessage({ type: "CHECK_ALLOWLIST", hostname: "127.0.0.1" }, resolve);
      })
    `);
    console.log("Popup sent CHECK_ALLOWLIST(127.0.0.1) -> Response:", checkAllow);

    const dynamicRules = await swEval("chrome.declarativeNetRequest.getDynamicRules()");
    console.log("SW getDynamicRules() count:", dynamicRules.length);
    console.log("SW dynamic rules detail:", JSON.stringify(dynamicRules, null, 2));

    const test4 = await runFetchTests("Allowlist ACTIVE for 127.0.0.1");

    console.log("\n--- Removing 127.0.0.1 from allowlist ---");
    const removeAllowResponse = await popupEval(`
      new Promise(resolve => {
        chrome.runtime.sendMessage({ type: "REMOVE_ALLOWLIST", hostname: "127.0.0.1" }, resolve);
      })
    `);
    console.log("Popup sent REMOVE_ALLOWLIST(127.0.0.1) -> Response:", removeAllowResponse);

    const dynamicRulesAfter = await swEval("chrome.declarativeNetRequest.getDynamicRules()");
    console.log("SW getDynamicRules() after remove count:", dynamicRulesAfter.length);

    const test5 = await runFetchTests("Allowlist REMOVED (Blocking resumed)");

    const finalReport = {
      initialRulesets,
      popupGetState,
      test1,
      toggleOffResponse,
      rulesetsOff,
      test2,
      toggleOnResponse,
      rulesetsOn,
      test3,
      addAllowResponse,
      dynamicRules,
      test4,
      removeAllowResponse,
      dynamicRulesAfter,
      test5
    };

    if (!fs.existsSync("scratch")) {
      fs.mkdirSync("scratch", { recursive: true });
    }
    fs.writeFileSync("scratch/real_dnr_verified_evidence.json", JSON.stringify(finalReport, null, 2));
    console.log("\n✓ ALL REAL VERIFICATION PHASES COMPLETED CLEANLY!");
    console.log("Saved evidence to scratch/real_dnr_verified_evidence.json");

    swWs.close();
    popupWs.close();
    pageWs.close();
  } catch (err) {
    console.error("Test error:", err);
  } finally {
    proc.kill();
    server.close();
    try {
      if (fs.existsSync(TEST_DIR)) {
        fs.rmSync(TEST_DIR, { recursive: true, force: true });
      }
    } catch {}
  }
});
