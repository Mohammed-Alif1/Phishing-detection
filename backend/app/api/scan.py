from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from urllib.parse import urlparse, unquote

import ipaddress
import json
import os
import re

import joblib
import pandas as pd

router = APIRouter()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_FILE = os.path.normpath(
    os.path.join(BASE_DIR, "..", "ml", "phishing_model.joblib")
)

THRESHOLD_FILE = os.path.normpath(
    os.path.join(BASE_DIR, "..", "ml", "model_threshold.json")
)

DEFAULT_ML_THRESHOLD = 0.24

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "is_https",
    "dot_count",
    "hyphen_count",
    "has_at_symbol",
    "is_ip",
    "digit_count",
    "keyword_count",
    "path_length",
    "num_slashes",
]


# --------------------------------------------------
# LOAD MODEL
# --------------------------------------------------

try:
    model = joblib.load(MODEL_FILE)
    print(f"[INFO] ML model loaded: {MODEL_FILE}")
except Exception as exc:
    print(f"[WARN] ML model could not be loaded: {exc}")
    model = None


# --------------------------------------------------
# LOAD MODEL THRESHOLD CONFIGURATION
# --------------------------------------------------

ml_threshold = DEFAULT_ML_THRESHOLD

try:
    with open(THRESHOLD_FILE, "r", encoding="utf-8") as file:
        threshold_config = json.load(file)

    configured_threshold = float(threshold_config["threshold"])

    if not 0.0 <= configured_threshold <= 1.0:
        raise ValueError("Threshold must be between 0 and 1.")

    configured_features = threshold_config.get("feature_columns")

    if configured_features and configured_features != FEATURE_COLUMNS:
        raise ValueError(
            "Threshold configuration feature columns do not match "
            "the scanner's feature columns."
        )

    ml_threshold = configured_threshold

    print(
        f"[INFO] ML threshold loaded: {ml_threshold:.2f} "
        f"(model={threshold_config.get('model', 'unknown')})"
    )

except FileNotFoundError:
    print(
        f"[WARN] Threshold config not found: {THRESHOLD_FILE}. "
        f"Using default threshold {DEFAULT_ML_THRESHOLD:.2f}."
    )

except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
    print(
        f"[WARN] Invalid threshold configuration: {exc}. "
        f"Using default threshold {DEFAULT_ML_THRESHOLD:.2f}."
    )


# --------------------------------------------------
# DETECTION CONFIGURATION
# --------------------------------------------------

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "update", "account", "bank", "confirm",
    "password", "signin", "webscr", "payment", "wallet", "authentication",
    "recover", "billing", "unlock", "validate", "support", "reset"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "click", "country", "gq", "tk", "work",
    "support", "stream", "xin", "rest", "fit"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly"
}

BRAND_DOMAINS = {
    "paypal": ("paypal.com",),
    "microsoft": (
        "microsoft.com",
        "live.com",
        "office.com",
        "microsoftonline.com",
    ),
    "apple": ("apple.com", "icloud.com"),
    "amazon": (
        "amazon.com",
        "amazon.in",
        "amazon.co.uk",
        "amazon.de",
    ),
    "google": ("google.com", "google.co.in", "gmail.com"),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
}


class ScanRequest(BaseModel):
    url: str


# --------------------------------------------------
# URL UTILITIES
# --------------------------------------------------

def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_local_or_private(hostname: str) -> bool:
    if hostname.lower() in {
        "localhost",
        "localhost.localdomain",
    }:
        return True

    try:
        address = ipaddress.ip_address(hostname)

        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
        )

    except ValueError:
        return False


# --------------------------------------------------
# FEATURE EXTRACTION
# --------------------------------------------------

def extract_features(url: str) -> dict:
    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()
    full_url = unquote(url).lower()

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "is_https": int(parsed.scheme.lower() == "https"),
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "has_at_symbol": int("@" in url),
        "is_ip": int(is_ip_address(hostname)),
        "digit_count": sum(char.isdigit() for char in url),
        "keyword_count": sum(
            1 for keyword in SUSPICIOUS_KEYWORDS
            if keyword in full_url
        ),
        "path_length": len(parsed.path or ""),
        "num_slashes": url.count("/"),
    }


# --------------------------------------------------
# HEURISTIC ANALYSIS
# --------------------------------------------------

def analyze_heuristics(
    url: str,
    parsed,
    feats: dict,
) -> tuple[int, list[str], bool]:

    host = (parsed.hostname or "").lower().rstrip(".")
    path_and_query = f"{parsed.path}?{parsed.query}".lower()

    reasons = []
    score = 0
    brand_impersonation = False

    if feats["has_at_symbol"]:
        score += 30
        reasons.append(
            "URL contains an '@' symbol, which can disguise "
            "the destination host."
        )

    if feats["is_ip"]:
        score += 28
        reasons.append(
            "The hostname is a raw IP address rather than "
            "a conventional domain."
        )

    if host.startswith("xn--") or ".xn--" in host:
        score += 22
        reasons.append(
            "Punycode hostname detected; inspect for "
            "look-alike Unicode characters."
        )

    if feats["is_https"] == 0:
        score += 8
        reasons.append(
            "The URL does not use HTTPS. This is a warning signal, "
            "not proof of phishing."
        )

    if feats["url_length"] > 180:
        score += 14
        reasons.append(
            "The URL is unusually long (over 180 characters)."
        )

    elif feats["url_length"] > 100:
        score += 8
        reasons.append(
            "The URL is longer than 100 characters."
        )

    if feats["hyphen_count"] >= 3:
        score += 10
        reasons.append(
            "The URL contains several hyphens, which can occur "
            "in deceptive domains."
        )

    if feats["dot_count"] >= 4:
        score += 10
        reasons.append(
            "The hostname has many dot-separated labels/subdomains."
        )

    elif feats["dot_count"] >= 3:
        score += 5
        reasons.append(
            "The hostname has multiple subdomain levels."
        )

    if feats["keyword_count"] > 0:
        keyword_score = min(12, feats["keyword_count"] * 4)
        score += keyword_score

        reasons.append(
            f"Contains {feats['keyword_count']} security-sensitive "
            "URL token(s); these are contextual signals, not proof."
        )

    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    if tld in SUSPICIOUS_TLDS:
        score += 12
        reasons.append(
            f"The .{tld} top-level domain is less common "
            "and deserves additional scrutiny."
        )

    if any(
        host == shortener or host.endswith("." + shortener)
        for shortener in SHORTENERS
    ):
        score += 8
        reasons.append(
            "A URL-shortening service hides the final destination "
            "until expanded."
        )

    if re.search(r"%[0-9a-fA-F]{2}", url):
        score += 6
        reasons.append(
            "Percent-encoded characters are present; "
            "check the decoded destination."
        )

    if parsed.port and parsed.port not in (80, 443):
        score += 8
        reasons.append(
            f"The URL uses a non-standard web port ({parsed.port})."
        )

    for brand, domains in BRAND_DOMAINS.items():
        if brand in host:
            legitimate_domain = any(
                host == domain or host.endswith("." + domain)
                for domain in domains
            )

            if not legitimate_domain:
                score += 38
                brand_impersonation = True

                reasons.append(
                    f"Possible {brand.title()} impersonation: "
                    "the brand appears in the hostname, but the "
                    "hostname does not end in an approved "
                    f"{brand.title()} domain."
                )
                break

    if any(
        token in path_and_query
        for token in (
            "password",
            "credential",
            "signin",
            "verify-account",
            "session=",
        )
    ):
        score += 5

        if not any(
            "security-sensitive URL token" in reason
            for reason in reasons
        ):
            reasons.append(
                "The path or query includes a credential/account-related term."
            )

    return min(100, score), reasons, brand_impersonation


# --------------------------------------------------
# MACHINE LEARNING INFERENCE
# --------------------------------------------------

def get_model_result(feats: dict):
    """
    Returns:
        model_score: phishing score from 0 to 100, or None
        ml_prediction: 'Phishing', 'Legitimate', or None

    The configured threshold is applied to the raw probability,
    not to the rounded 0-100 score.
    """

    if model is None:
        return None, None

    try:
        row = pd.DataFrame(
            [[feats[column] for column in FEATURE_COLUMNS]],
            columns=FEATURE_COLUMNS,
        )

        probabilities = model.predict_proba(row)[0]
        classes = list(getattr(model, "classes_", [0, 1]))

        if 1 not in classes:
            raise ValueError(
                "Loaded model does not contain phishing class label 1."
            )

        phishing_index = classes.index(1)
        phishing_probability = float(probabilities[phishing_index])

        model_score = round(phishing_probability * 100)

        if phishing_probability >= ml_threshold:
            ml_prediction = "Phishing"
        else:
            ml_prediction = "Legitimate"

        return model_score, ml_prediction

    except Exception as exc:
        print(
            f"[WARN] ML inference failed; "
            f"using heuristic result: {exc}"
        )
        return None, None


# --------------------------------------------------
# SCAN ENDPOINT
# --------------------------------------------------

@router.post("/scan")
def scan(request: ScanRequest):

    raw_url = request.url.strip()

    if not raw_url or len(raw_url) > 4096:
        raise HTTPException(
            status_code=422,
            detail="Provide a URL between 1 and 4096 characters.",
        )

    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raise HTTPException(
            status_code=422,
            detail="Only HTTP and HTTPS URLs can be scanned.",
        )

    try:
        parsed = urlparse(raw_url)
        hostname = parsed.hostname or ""

        # Accessing .port can raise ValueError for malformed ports.
        _ = parsed.port

    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="The URL format or port is invalid.",
        )

    if not hostname:
        raise HTTPException(
            status_code=422,
            detail="The URL does not contain a valid hostname.",
        )

    feats = extract_features(raw_url)

    heuristic_score, reasons, brand_impersonation = analyze_heuristics(
        raw_url,
        parsed,
        feats,
    )

    # Local/private destinations are deliberately unrated.
    if is_local_or_private(hostname):
        return {
            "url": raw_url,
            "host": hostname,
            "riskScore": None,
            "prediction": "Local / unrated",
            "modelScore": None,
            "mlPrediction": None,
            "mlThreshold": ml_threshold,
            "heuristicScore": heuristic_score,
            "reasons": [
                "This is a localhost, loopback, or private-network "
                "address. Public phishing classification is not "
                "meaningful for this destination."
            ],
            "assessment": "unrated",
            "modelAvailable": model is not None,
        }

    model_score, ml_prediction = get_model_result(feats)

    # Preserve the existing hybrid risk calculation.
    if model_score is None:
        risk_score = heuristic_score

    else:
        # Demo-oriented hybrid score, not a calibrated probability.
        risk_score = round(
            0.35 * model_score
            + 0.65 * heuristic_score
        )

        if brand_impersonation:
            risk_score = max(risk_score, 65)

        if feats["has_at_symbol"] or feats["is_ip"]:
            risk_score = max(risk_score, 60)

    risk_score = max(0, min(100, risk_score))

    # Final user-facing classification remains based on hybrid risk.
    if risk_score >= 65:
        prediction = "High risk"
        assessment = "high"

    elif risk_score >= 35:
        prediction = "Suspicious"
        assessment = "medium"

    else:
        prediction = "Low risk"
        assessment = "low"

    if not reasons:
        reasons.append(
            "No strong lexical warning signals were detected in this URL."
        )

    print(
        f"[SCAN] host={hostname!r} "
        f"heuristic={heuristic_score} "
        f"model={model_score} "
        f"ml_prediction={ml_prediction} "
        f"ml_threshold={ml_threshold:.2f} "
        f"risk={risk_score} "
        f"result={prediction}"
    )

    return {
        "url": raw_url,
        "host": hostname,
        "riskScore": risk_score,
        "prediction": prediction,
        "modelScore": model_score,
        "mlPrediction": ml_prediction,
        "mlThreshold": ml_threshold,
        "heuristicScore": heuristic_score,
        "reasons": reasons,
        "assessment": assessment,
        "modelAvailable": model is not None,
        "scoreNote": (
            "Risk score combines the available ML output and URL "
            "heuristics; it is not a calibrated probability."
            if model_score is not None
            else "ML model unavailable; this score uses URL heuristics "
            "only and is not a calibrated probability."
        ),
    }