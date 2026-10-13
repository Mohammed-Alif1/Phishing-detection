# SentinelAI: public dataset + grouped model evaluation patch

This patch adds a reproducible path to build a larger URL-only dataset and evaluate models without randomly leaking URLs from the same domain across splits.

## Dataset selected

UCI PhiUSIIL Phishing URL (Website) Dataset, UCI dataset ID 967:
https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset

The official page reports 235,795 rows (134,850 legitimate and 100,945 phishing) and a CC BY 4.0 license. The preparation script fetches the dataset through `ucimlrepo`, uses only the raw `URL` column, and recomputes the project's existing 11 URL-only features. It does **not** use page-source-derived columns the extension cannot access.

Important: UCI PhiUSIIL's original target convention is `1=legitimate`, `0=phishing`. This project uses `0=legitimate`, `1=phishing`, so the script deliberately remaps labels.

## Files

- `backend/ml/prepare_public_dataset.py`: fetches, normalizes, deduplicates and labels the public dataset; writes `data/dataset.csv` and `data/dataset_manifest.json`.
- `backend/ml/train_model_grouped.py`: trains Random Forest, Extra Trees and Logistic Regression; selects model/threshold on validation data; reports metrics on a separate domain-grouped test split; writes `reports/model_evaluation.json`, `model_threshold.json` and `phishing_model.joblib`. The scanner's hard-coded threshold must be updated to read `model_threshold.json` before the selected threshold is reflected in live classification; do not assume the threshold is automatically wired into the existing scanner.
- `backend/ml/requirements-ml.txt`: extra dependencies for data preparation/training.

## Windows PowerShell commands

Run from the repository root (`D:\projects\Phishing-detection`):

```powershell
.\backend\.venv\Scripts\python.exe -m pip install -r backend\ml\requirements-ml.txt
.\backend\.venv\Scripts\python.exe backend\ml\prepare_public_dataset.py
```

Review the generated `backend\ml\data\dataset_manifest.json`, then train/evaluate:

```powershell
.\backend\.venv\Scripts\python.exe backend\ml\train_model_grouped.py
```

Training writes the model file used by the backend, so make a backup of the existing `backend\ml\phishing_model.joblib` first. The script only replaces it after training/evaluation finishes successfully.

## Interpretation and limitations

- `label=1` means phishing; `label=0` means legitimate in the generated project dataset.
- Splits are grouped by registrable domain using `StratifiedGroupKFold`; overlap counts are saved in the report and asserted to be zero.
- Threshold selection uses validation data only. Final test metrics do not select the model.
- This is a stronger evaluation than a random row split, but not proof of future real-world detection performance.
- The project risk score is not a calibrated probability.
- The downloaded dataset is not a live threat-intelligence feed.
- Keep the dataset source, license and attribution with any report or redistribution.
