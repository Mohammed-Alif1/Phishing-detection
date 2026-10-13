# SentinelAI update: phishing evaluation + basic ad/tracker blocking

## What's included

- A Chrome Manifest V3 static `declarativeNetRequest` ruleset for selected advertising/tracking domains.
- A real ON/OFF toggle persisted in `chrome.storage.local`.
- A dataset builder that consumes source CSVs instead of fabricating synthetic phishing URLs.
- A model training script that uses hostname-grouped train/validation/test splits, selects an evaluation threshold on validation data, and reports holdout metrics.
- The existing phishing scanner and popup are retained. The implementation/scoring-method note is no longer shown as if it were a threat signal.

## Dataset setup

The uploaded project did **not** contain `backend/ml/data/` or its source CSVs. Consequently, no new model can honestly be trained or evaluated from the uploaded files alone.

Create `backend/ml/data/` and place:

1. `verified_online.csv`: the official PhishTank verified-online CSV export, which has a `url` column and typically `verified`/`online` columns.
2. `top-1m.csv`: a Tranco top-sites CSV with two columns: rank, domain and no header.

Official source information:
- PhishTank data downloads: https://www.phishtank.org/developer_info.php
- Tranco list service: https://tranco-list.eu/

PhishTank may rate-limit downloads without an application key. Download data through its official instructions and comply with its terms. Do not use or open URLs in the dataset during preparation.

Then, from the project root:

```powershell
cd backend
python -m pip install -r requirements.txt
cd ml
python build_dataset.py
python train_model.py
```

The builder:
- filters invalid URLs and, when columns exist, unverified/offline PhishTank records;
- deduplicates URLs and hostnames;
- excludes hostnames present in both source classes;
- uses one HTTPS root URL per Tranco domain instead of random synthetic paths;
- records source provenance in each row.

**Important label caveat:** Tranco identifies popular domains, not guaranteed-benign domains. Treat those as a popular-domain proxy class, not verified legitimate labels. Metrics are specific to this dataset and may not generalize to current phishing campaigns.

The trainer groups splits by hostname/domain to reduce direct domain leakage. It reports accuracy, precision, recall, F1, ROC-AUC, confusion matrix counts, and feature importance. The risk score exposed by the API remains a hybrid score and is not a calibrated probability. The validation-selected threshold is for the model evaluation report; it is not a claim of universal optimality.

## Ad & tracker protection

The extension uses `declarativeNetRequest` static rules from `public/rules/adblock_rules.json`. The popup toggle enables/disables the ruleset through the service worker. This is a modest domain-based blocker, not a full filter-list engine; some ads will remain, and some sites may behave differently when requests are blocked.

To load/reload:
1. Run `npm run build` in the project root.
2. Open `chrome://extensions`.
3. Enable Developer mode.
4. Click Reload on SentinelAI, or load the generated `dist` folder if needed.
5. Open the popup and toggle **Basic ad blocker** to verify ON/OFF behavior.

## Backend

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --port 8000
```

The extension scans URL text only. It does not visit or open the URL entered in the scan field.

## Limitations

- No dataset was bundled in the uploaded project, so this patch does not include new accuracy claims or a retrained model.
- URL-only features can miss sophisticated phishing and can flag benign unusual URLs.
- There is no live Google Safe Browsing, DNS/WHOIS reputation, page-content inspection, or guarantee of safety.
- Static ad-domain rules cannot block every ad.
