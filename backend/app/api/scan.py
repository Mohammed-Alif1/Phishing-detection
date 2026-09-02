from fastapi import APIRouter
from pydantic import BaseModel
from urllib.parse import urlparse
import re

router = APIRouter()


class ScanRequest(BaseModel):
    url: str


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "confirm", "password", "signin", "webscr",
    "paypal", "ebay", "amazon", "apple", "microsoft"
]


def is_ip_address(hostname: str) -> bool:
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, hostname))


def analyze_url(url: str):
    reasons = []
    score = 0

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    full_url = url.lower()

    # 1. HTTPS check
    if parsed.scheme != "https":
        score += 20
        reasons.append("Website does not use HTTPS")

    # 2. URL length
    if len(url) > 75:
        score += 15
        reasons.append("URL is unusually long")

    # 3. Number of dots in hostname (subdomain abuse)
    dot_count = hostname.count(".")
    if dot_count > 3:
        score += 15
        reasons.append("Excessive number of subdomains")

    # 4. '@' symbol trick
    if "@" in url:
        score += 25
        reasons.append("URL contains '@' symbol, a common phishing trick")

    # 5. IP address instead of domain
    if is_ip_address(hostname):
        score += 30
        reasons.append("Domain is an IP address instead of a name")

    # 6. Suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    if found_keywords:
        score += 10 * len(found_keywords)
        reasons.append(
            f"Contains suspicious keyword(s): {', '.join(found_keywords)}"
        )

    # 7. Hyphens in hostname (typosquatting pattern)
    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        score += 15
        reasons.append("Domain contains multiple hyphens")

    # Cap score at 100
    score = min(score, 100)

    if not reasons:
        reasons.append("No suspicious indicators found")

    if score >= 60:
        prediction = "Phishing"
    elif score >= 30:
        prediction = "Suspicious"
    else:
        prediction = "Safe"

    confidence = min(60 + score // 2, 99)

    return score, prediction, confidence, reasons


@router.post("/scan")
def scan(request: ScanRequest):
    score, prediction, confidence, reasons = analyze_url(request.url)

    return {
        "riskScore": score,
        "prediction": prediction,
        "confidence": confidence,
        "reasons": reasons,
        "url": request.url
    }