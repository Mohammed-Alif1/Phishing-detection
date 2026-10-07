import joblib
import os
from urllib.parse import urlparse
import re
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(BASE_DIR, "phishing_model.joblib")

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


def is_ip_address(hostname):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname or ""))


def extract_features(url):
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


model = joblib.load(MODEL_FILE)


def predict_url(url):
    feats = extract_features(url)
    row = pd.DataFrame([[feats[col] for col in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
    pred = model.predict(row)[0]
    proba = model.predict_proba(row)[0]
    label = "PHISHING" if pred == 1 else "SAFE"
    print(f"{label:10s}  conf={max(proba)*100:.1f}%   {url}")


def debug_url(url):
    feats = extract_features(url)
    row = pd.DataFrame([[feats[col] for col in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
    proba = model.predict_proba(row)[0]
    print(f"\nURL: {url}")
    print(f"Phishing probability: {proba[1]*100:.1f}%")
    for k, v in feats.items():
        print(f"  {k}: {v}")


print("=== Quick predictions ===")
test_urls = [
    "https://www.google.com/search?q=weather",
    "https://amazon.com/account/orders/12345",
    "https://github.com/login",
    "http://192.168.1.5/login/verify-account",
    "http://secure-paypal@paypal.com.tk/confirm",
    "http://verify-account-secure.com/paypal",
    "https://monprime-espace.com/pages/desktop/remboursement/prime/confirmation.php",
]
for url in test_urls:
    predict_url(url)

print("\n=== Detailed debug (trailing-slash URLs, matching real browser behavior) ===")
debug_url("https://monkeytype.com/")
debug_url("https://www.youtube.com/")
debug_url("https://google.com/")