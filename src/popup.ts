const website = document.getElementById("website");
const title = document.getElementById("title");
const status = document.getElementById("status");

const scanBtn = document.getElementById("scanBtn");
const riskScore = document.getElementById("riskScore");
const prediction = document.getElementById("prediction");
const confidence = document.getElementById("confidence");

let currentUrl = "";

chrome.tabs.query(
  {
    active: true,
    currentWindow: true,
  },
  (tabs) => {
    const tab = tabs[0];

    if (!tab || !tab.url) {
      if (status) {
        status.textContent = "No active tab.";
      }
      return;
    }

    currentUrl = tab.url;

    const url = new URL(tab.url);

    if (website) {
      website.textContent = url.hostname;
    }

    if (title) {
      title.textContent = tab.title || "Unknown";
    }

    if (status) {
      status.textContent = "🟢 Ready to Scan";
    }
  }
);


scanBtn?.addEventListener("click", async () => {

  if (!currentUrl) {
    if (status) {
      status.textContent = "No URL available.";
    }
    return;
  }

  if (status) {
    status.textContent = "🔄 Scanning...";
  }

  if (scanBtn instanceof HTMLButtonElement) {
    scanBtn.disabled = true;
  }

  try {

    const response = await fetch(
      "http://127.0.0.1:8000/api/scan",
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify({
          url: currentUrl,
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`HTTP error: ${response.status}`);
    }

    const data = await response.json();

    console.log("Scan result:", data);

    if (riskScore) {
      riskScore.textContent = `${data.riskScore}%`;
    }

    if (prediction) {
      prediction.textContent = data.prediction;
    }

    if (confidence) {
      confidence.textContent = `${data.confidence}%`;
    }

    if (status) {
      status.textContent = "✅ Scan Complete";
    }

  } catch (error) {

    console.error("Scan failed:", error);

    if (status) {
      status.textContent = "❌ Scan failed";
    }

  } finally {

    if (scanBtn instanceof HTMLButtonElement) {
      scanBtn.disabled = false;
    }

  }
});