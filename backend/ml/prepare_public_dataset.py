"""
Prepare a reproducible URL-feature dataset from UCI PhiUSIIL (dataset 967).

Label mapping for this project's convention:
  label=1 -> phishing
  label=0 -> legitimate

The official UCI dataset uses label 1 for legitimate and 0 for phishing.
We recompute the project's 11 URL-only features from the URL itself, rather
than using precomputed page/content features that the scanner cannot reproduce.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import pandas as pd
import tldextract
from ucimlrepo import fetch_ucirepo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "dataset.csv")
MANIFEST_FILE = os.path.join(DATA_DIR, "dataset_manifest.json")
RANDOM_SEED = 42

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "confirm", "password", "signin", "webscr",
    "paypal", "ebay", "amazon", "apple", "microsoft",
]
FEATURE_COLUMNS = [
    "url_length", "hostname_length", "is_https", "dot_count",
    "hyphen_count", "has_at_symbol", "is_ip", "digit_count",
    "keyword_count", "path_length", "num_slashes",
]

# Disable network fetching of the Public Suffix List; tldextract uses its
# packaged snapshot so preprocessing remains reproducible/offline after install.
TLD = tldextract.TLDExtract(suffix_list_urls=())


def normalize_url(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value or value.lower() in {"nan", "none", "null"}:
        return None
    if "://" not in value:
        value = "http://" + value
    try:
        p = urlparse(value)
        if p.scheme.lower() not in {"http", "https"} or not p.hostname:
            return None
        # Preserve path/query semantics; normalize scheme/host and remove fragment.
        host = p.hostname.lower().rstrip(".")
        port = p.port
        netloc = host
        if port and not ((p.scheme.lower() == "http" and port == 80) or
                         (p.scheme.lower() == "https" and port == 443)):
            netloc = f"{host}:{port}"
        if p.username or p.password:
            # Keep the URL's user-info marker because it can be a phishing signal,
            # but avoid credentials from being mistaken for the hostname.
            userinfo = p.username or ""
            if p.password:
                userinfo += ":" + p.password
            netloc = f"{userinfo}@{netloc}"
        normalized = urlunparse((p.scheme.lower(), netloc, p.path or "/", p.params, p.query, ""))
        return normalized
    except (ValueError, UnicodeError):
        return None


def is_ip_address(hostname: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname or ""))


def extract_features(url: str) -> dict:
    p = urlparse(url)
    hostname = p.hostname or ""
    lowered = url.lower()
    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "is_https": int(p.scheme.lower() == "https"),
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "has_at_symbol": int("@" in url),
        "is_ip": int(is_ip_address(hostname)),
        "digit_count": sum(c.isdigit() for c in url),
        "keyword_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered),
        "path_length": len(p.path or ""),
        "num_slashes": url.count("/"),
    }


def domain_group(url: str) -> str:
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    if is_ip_address(host) or host == "localhost":
        return host
    result = TLD(host)
    return result.top_domain_under_public_suffix or host


def main() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    print("Fetching UCI PhiUSIIL Phishing URL (Website) dataset (ID 967)...")
    print("Requires internet access on this computer and the ucimlrepo package.")
    dataset = fetch_ucirepo(id=967)
    features = dataset.data.features
    targets = dataset.data.targets
    if "URL" not in features.columns:
        raise ValueError(f"Expected a URL column; got columns: {list(features.columns)}")
    if targets is None or targets.shape[1] < 1:
        raise ValueError("UCI dataset did not provide a target column.")

    raw_urls = features["URL"].tolist()
    raw_labels = targets.iloc[:, 0].tolist()
    rows = []
    skipped = 0
    for raw_url, raw_label in zip(raw_urls, raw_labels):
        url = normalize_url(raw_url)
        try:
            original_label = int(raw_label)
        except (TypeError, ValueError):
            skipped += 1
            continue
        # UCI PhiUSIIL: 1=legitimate, 0=phishing. Project convention: 1=phishing.
        if url is None or original_label not in (0, 1):
            skipped += 1
            continue
        label = 1 if original_label == 0 else 0
        row = {"url": url, **extract_features(url), "label": label,
               "domain_group": domain_group(url)}
        rows.append(row)

    df = pd.DataFrame(rows)
    before = len(df)
    # Remove exact normalized URL duplicates with the same label.
    conflicting = df.groupby("url")["label"].nunique()
    conflicting_urls = set(conflicting[conflicting > 1].index)
    conflict_count = len(conflicting_urls)
    df = df[~df["url"].isin(conflicting_urls)].copy()
    df = df.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    after = len(df)
    if df.empty or df["label"].nunique() != 2:
        raise ValueError("After cleaning, the dataset must contain both classes.")

    df.to_csv(OUTPUT_FILE, index=False)
    manifest = {
        "dataset_name": "PhiUSIIL Phishing URL (Website) Dataset",
        "uci_dataset_id": 967,
        "source": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset",
        "citation": "Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website) Dataset. UCI Machine Learning Repository. https://doi.org/10.1016/j.cose.2023.103545.",
        "license": "CC BY 4.0 (verify current terms on the official UCI page before redistribution)",
        "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_rows": int(len(raw_urls)),
        "rows_skipped_invalid_or_unusable": int(skipped),
        "rows_before_deduplication": int(before),
        "conflicting_label_urls_removed": int(conflict_count),
        "rows_after_deduplication": int(after),
        "class_mapping": {"0": "phishing", "1": "legitimate"},
        "project_label_mapping": {"0": "legitimate", "1": "phishing"},
        "class_counts_project_label": {str(int(k)): int(v) for k, v in df["label"].value_counts().sort_index().items()},
        "unique_domain_groups": int(df["domain_group"].nunique()),
        "feature_columns": FEATURE_COLUMNS,
        "notes": [
            "Only the raw URL column is used; webpage/content-derived UCI features are not used because this scanner only sees URLs.",
            "Exact normalized URL duplicates are removed. URLs with conflicting labels are removed.",
            "Domain groups are reserved for group-aware train/validation/test splitting.",
            "This dataset is not a live feed and may not represent current threats.",
        ],
    }
    with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print("\nDataset preparation complete.")
    print(f"Saved: {OUTPUT_FILE}")
    print(f"Manifest: {MANIFEST_FILE}")
    print(f"Rows source={len(raw_urls)}, before dedupe={before}, conflicting URLs removed={conflict_count}, final={after}")
    print("Project label counts (0=legitimate, 1=phishing):")
    print(df["label"].value_counts().sort_index().to_string())
    print(f"Unique domain groups: {df['domain_group'].nunique()}")
    print("\nNo model was trained by this script. Run train_model_grouped.py after reviewing the manifest.")


if __name__ == "__main__":
    main()
