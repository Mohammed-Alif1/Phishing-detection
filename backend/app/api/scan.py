from fastapi import APIRouter
from pydantic import BaseModel
from urllib.parse import urlparse
import re
import os
import joblib
import pandas as pd

router = APIRouter()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # backend/app
MODEL_FILE = os.path.join(BASE_DIR, "..", "ml", "phishing_model.joblib")

model = joblib.load(MODEL_FILE)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "confirm", "password", "signin", "webscr",
    "paypal", "ebay", "amazon", "apple", "microsoft"
]

FEATURE_COLUMNS = [
    "url_length", "hostname_length", "is_https", "dot_count",
    "hyphen_count", "has_at_symbol", "is_ip", "digit_count",
    "keyword_count", "path_length", "num_slashes",
]


class ScanRequest(BaseModel):
    url: str


def is_ip_address(hostname: str) -> bool:
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, hostname or ""))


def extract_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    full_url = url.lower()

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "is_https": 1 if parsed.scheme == "https" else 0,
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "has_at_symbol": 1 if "@" in url else 0,
        "is_ip": 1 if is_ip_address(hostname) else 0,
        "digit_count": sum(c.isdigit() for c in url),
        "keyword_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url),
        "path_length": len(parsed.path or ""),
        "num_slashes": url.count("/"),
    }


def build_reasons(feats: dict) -> list[str]:
    reasons = []
    if feats["is_https"] == 0:
        reasons.append("Website does not use HTTPS")
    if feats["is_ip"] == 1:
        reasons.append("Domain is an IP address instead of a name")
    if feats["has_at_symbol"] == 1:
        reasons.append("URL contains '@' symbol, a common phishing trick")
    if feats["hyphen_count"] >= 2:
        reasons.append("Domain contains multiple hyphens")
    if feats["keyword_count"] > 0:
        reasons.append(f"Contains {feats['keyword_count']} suspicious keyword(s)")
    if feats["url_length"] > 75:
        reasons.append("URL is unusually long")
    if not reasons:
        reasons.append("No suspicious indicators found")
    return reasons


@router.post("/scan")
def scan(request: ScanRequest):
    feats = extract_features(request.url)
    print(f"\n[DEBUG] Received URL: {repr(request.url)}")
    print(f"[DEBUG] Features: {feats}")

    row = pd.DataFrame([[feats[col] for col in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)

    proba = model.predict_proba(row)[0]
    phishing_probability = proba[1]

    PHISHING_THRESHOLD = 0.40  # lean toward catching more phishing, fewer missed threats

    pred = 1 if phishing_probability >= PHISHING_THRESHOLD else 0

    risk_score = int(phishing_probability * 100)
    confidence = int(max(proba) * 100)
    prediction = "Phishing" if pred == 1 else "Safe"

    print(f"[DEBUG] Phishing probability: {phishing_probability*100:.1f}%  ->  {prediction}\n")

    return {
        "riskScore": risk_score,
        "prediction": prediction,
        "confidence": confidence,
        "reasons": build_reasons(feats),
        "url": request.url,
    }