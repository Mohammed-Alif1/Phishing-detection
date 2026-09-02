import pandas as pd
from urllib.parse import urlparse
import re
import os
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

PHISHTANK_FILE = os.path.join(DATA_DIR, "verified_online.csv")
TRANCO_FILE = os.path.join(DATA_DIR, "top-1m.csv")
OUTPUT_FILE = os.path.join(DATA_DIR, "dataset.csv")

NUM_LEGIT_SAMPLES = 10000
RANDOM_SEED = 42

random.seed(RANDOM_SEED)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "confirm", "password", "signin", "webscr",
    "paypal", "ebay", "amazon", "apple", "microsoft"
]


LEGIT_PATH_TEMPLATES = [
    "",  
    "/",
    "/about",
    "/about-us",
    "/contact",
    "/products",
    "/products/{id}",
    "/blog",
    "/blog/{slug}",
    "/search?q={slug}",
    "/login",
    "/account",
    "/account/settings",
    "/account/orders/{id}",
    "/help/faq",
    "/support",
    "/news/{slug}",
    "/category/{slug}/item/{id}",
    "/user/{id}/profile",
    "/cart",
    "/checkout",
]

SLUG_WORDS = ["summer-sale", "new-arrivals", "guide", "review", "update-2026",
              "how-to", "top-10", "release-notes", "faq", "pricing"]


def random_path():
    template = random.choice(LEGIT_PATH_TEMPLATES)
    path = template.format(
        id=random.randint(100, 99999),
        slug=random.choice(SLUG_WORDS)
    )
    return path


def is_ip_address(hostname: str) -> bool:
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, hostname or ""))


def extract_features(url: str) -> dict:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return None

    full_url = url.lower()

    features = {
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
    return features


def build_legit_urls(domains):
    """Attach realistic paths to legitimate domains instead of leaving them all bare."""
    urls = []
    for domain in domains:
        path = random_path()
        scheme = "https"  # legit sites in Tranco top list are virtually all HTTPS today
        urls.append(f"{scheme}://{domain}{path}")
    return urls


def build_synthetic_phishing_variants(domains, n=1500):
    """
    Real PhishTank data barely contains IP-based or '@' URLs, so the model
    never learns those classic signals. We add a small number of synthetic
    examples using those exact tricks, based on real-looking domain patterns,
    purely so the model sees them during training.
    """
    synthetic = []
    sample_domains = random.sample(domains, min(n, len(domains)))

    for i, domain in enumerate(sample_domains):
        choice = i % 3
        if choice == 0:
            # fake IP address host
            ip = f"{random.randint(10,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            synthetic.append(f"http://{ip}/login/verify-account")
        elif choice == 1:
            # '@' trick pointing to a different real host after the @
            fake_prefix = random.choice(["secure", "login", "verify", "account-update"])
            synthetic.append(f"http://{fake_prefix}-{domain}@{domain}.tk/confirm")
        else:
            # hyphenated typosquat-style domain with suspicious keyword
            kw = random.choice(SUSPICIOUS_KEYWORDS)
            synthetic.append(f"http://{kw}-{domain.replace('.', '-')}-secure.com/{kw}")

    return synthetic


def build_dataset():
    print("Loading PhishTank data...")
    phish_df = pd.read_csv(PHISHTANK_FILE)
    phish_urls = phish_df["url"].dropna().unique().tolist()
    print(f"  {len(phish_urls)} phishing URLs loaded")

    print("Loading Tranco data...")
    tranco_df = pd.read_csv(TRANCO_FILE, header=None, names=["rank", "domain"])
    legit_domains = tranco_df["domain"].head(NUM_LEGIT_SAMPLES).tolist()

    print("Generating realistic legitimate URLs with paths...")
    legit_urls = build_legit_urls(legit_domains)
    print(f"  {len(legit_urls)} legitimate URLs prepared")

    print("Generating synthetic phishing variants (IP-based, '@' trick, typosquat)...")
    synthetic_phish = build_synthetic_phishing_variants(legit_domains, n=1500)
    print(f"  {len(synthetic_phish)} synthetic phishing URLs added")

    rows = []

    print("Extracting features from phishing URLs...")
    for url in phish_urls:
        feats = extract_features(url)
        if feats:
            feats["label"] = 1
            rows.append(feats)

    print("Extracting features from synthetic phishing URLs...")
    for url in synthetic_phish:
        feats = extract_features(url)
        if feats:
            feats["label"] = 1
            rows.append(feats)

    print("Extracting features from legitimate URLs...")
    for url in legit_urls:
        feats = extract_features(url)
        if feats:
            feats["label"] = 0
            rows.append(feats)

    dataset = pd.DataFrame(rows)
    dataset = dataset.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    dataset.to_csv(OUTPUT_FILE, index=False)
    print(f"\nDone. Saved {len(dataset)} rows to {OUTPUT_FILE}")
    print(dataset["label"].value_counts())


if __name__ == "__main__":
    build_dataset()