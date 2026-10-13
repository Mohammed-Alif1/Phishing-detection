# Training data (not bundled)

This project upload did not include the source dataset files. Do not invent or duplicate data to fill this folder.

Required files:
- `verified_online.csv`: official PhishTank verified-online CSV export, containing a `url` column.
- `top-1m.csv`: Tranco top-sites CSV with `rank,domain` columns and no header.

Official instructions:
- PhishTank downloads: https://www.phishtank.org/developer_info.php
- Tranco: https://tranco-list.eu/

After downloading and placing the files here, run `python build_dataset.py` followed by `python train_model.py` from `backend/ml`.

Caution: Tranco is a popularity ranking, not a verified benign-domain feed. The builder labels these as a popular-domain proxy. Report that limitation when presenting metrics.
