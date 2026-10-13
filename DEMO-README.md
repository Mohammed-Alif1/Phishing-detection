# SentinelAI demo overlay

This overlay improves the extension popup presentation and adds transparent URL heuristics to the existing FastAPI scanner.

## Apply

1. Back up your current project folder or commit your current work.
2. Extract this ZIP into the root of your cloned `Phishing-detection` repository.
3. Allow the files to overwrite:
   - `src/popup.html`
   - `src/popup.css`
   - `src/popup.ts`
   - `backend/app/api/scan.py`
4. Rebuild the extension from the repository root:
   ```powershell
   npm run build
   ```
5. Open `chrome://extensions`, enable Developer mode, and click **Reload** on the extension. If the `dist` folder was not loaded before, use **Load unpacked** and select `dist`.
6. Restart the backend in PowerShell:
   ```powershell
   cd .\backend
   .\.venv\Scripts\Activate.ps1
   python -m uvicorn app.main:app --reload --port 8000
   ```

## Demo test URLs

Paste these into the popup's URL input. The extension sends the string to the local API and does not open the URL.

- Low-risk example: `https://www.google.com/`
- Brand impersonation pattern: `https://paypal.com.security-check.example/login`
- Brand impersonation pattern: `https://microsoft-login-check.example/verify-account`

The `.example` top-level domain is reserved for documentation/examples, so these sample URLs are not live sites.

## Important limitations

- The combined risk score is a demo-oriented blend of the existing model and explicit URL heuristics. It is **not a calibrated probability** and should not be advertised as proven detection accuracy.
- Localhost and private-network URLs are returned as unrated rather than being mislabeled safe.
- This does not query live threat-intelligence feeds, WHOIS, DNS reputation, or a safe-browsing service.
- Do not claim production readiness. The next step is a proper held-out evaluation using a recent, deduplicated, labeled dataset, reporting precision, recall, F1, and false-positive/false-negative counts.
