"""
PhishGuard - Feature Extraction Module
Extracts 11 distinct numerical Machine Learning features from a website URL.

All features are purely numerical to serve as inputs for classification algorithms
(Logistic Regression, Decision Tree, Random Forest).
"""

import re
from urllib.parse import urlparse
import numpy as np

# List of sensitive security-related keywords frequently abused in phishing attacks
SUSPICIOUS_WORDS = [
    "login", "verify", "account", "update",
    "secure", "bank", "signin", "confirm"
]

# Exact feature ordering used across training, evaluation, and inference
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special_chars",
    "num_slashes",
    "has_https",
    "is_ip_address",
    "num_subdomains",
    "suspicious_words_count"
]

# IPv4 address regex pattern
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$"
)

def normalize_url(url: str) -> str:
    """Ensure URL has a scheme for proper parsing."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        # Default to http:// if no scheme is provided for parsing purposes
        return "http://" + url
    return url

def extract_features_dict(url: str) -> dict:
    """
    Extracts numerical features from a URL and returns them as a key-value dictionary.
    """
    raw_url = url.strip()
    norm_url = normalize_url(raw_url)
    
    try:
        parsed = urlparse(norm_url)
        domain = parsed.netloc.split(":")[0]  # Remove port if present
    except Exception:
        domain = ""

    url_lower = norm_url.lower()

    # 1. Total URL length
    url_length = len(raw_url)

    # 2. Domain length
    domain_length = len(domain)

    # 3. Number of dots
    num_dots = raw_url.count(".")

    # 4. Number of hyphens
    num_hyphens = raw_url.count("-")

    # 5. Number of digits
    num_digits = sum(1 for c in raw_url if c.isdigit())

    # 6. Number of special characters (@, ?, =, _, %, &, +, #)
    special_chars = set("@?=_&+#%")
    num_special_chars = sum(1 for c in raw_url if c in special_chars)

    # 7. Number of slashes
    num_slashes = raw_url.count("/")

    # 8. Presence of HTTPS (1 if HTTPS, 0 if HTTP or absent)
    has_https = 1 if raw_url.lower().startswith("https://") else 0

    # 9. Presence of IP address instead of domain
    is_ip_address = 1 if IPV4_PATTERN.match(domain) else 0

    # 10. Number of subdomains
    # Split domain by dot; typical example: sub2.sub1.example.com -> 2 subdomains
    domain_parts = [part for part in domain.split(".") if part]
    if is_ip_address or len(domain_parts) <= 2:
        num_subdomains = 0
    else:
        num_subdomains = len(domain_parts) - 2

    # 11. Presence/count of suspicious words
    matched_words = [word for word in SUSPICIOUS_WORDS if word in url_lower]
    suspicious_words_count = len(matched_words)

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "num_special_chars": num_special_chars,
        "num_slashes": num_slashes,
        "has_https": has_https,
        "is_ip_address": is_ip_address,
        "num_subdomains": num_subdomains,
        "suspicious_words_count": suspicious_words_count,
        "_matched_suspicious_words": matched_words,  # Helper metadata for indicators
        "_domain": domain
    }

def extract_features(url: str) -> np.ndarray:
    """
    Extracts features and returns a 1D numpy array in standard feature order.
    Suitable for scikit-learn model input.
    """
    feat_dict = extract_features_dict(url)
    return np.array([feat_dict[name] for name in FEATURE_NAMES], dtype=float)

def get_suspicious_indicators(url: str, feat_dict: dict = None) -> list:
    """
    Generates human-readable educational indicators explaining why a URL
    exhibits suspicious or legitimate characteristics.
    Used for the frontend educational card and viva demonstrations.
    """
    if feat_dict is None:
        feat_dict = extract_features_dict(url)

    indicators = []

    if feat_dict["is_ip_address"] == 1:
        indicators.append({
            "type": "danger",
            "title": "Raw IP Address Used",
            "description": f"Domain '{feat_dict['_domain']}' is a numeric IP address instead of a registered domain name."
        })

    if feat_dict["has_https"] == 0:
        indicators.append({
            "type": "warning",
            "title": "No HTTPS Encryption",
            "description": "The URL uses unencrypted HTTP protocol, leaving communication vulnerable."
        })

    if feat_dict["num_subdomains"] >= 2:
        indicators.append({
            "type": "danger" if feat_dict["num_subdomains"] > 3 else "warning",
            "title": "Multiple Subdomains",
            "description": f"Found {feat_dict['num_subdomains']} subdomains, a common tactic to impersonate legitimate brand URLs."
        })

    if feat_dict["suspicious_words_count"] > 0:
        words = ", ".join([f"'{w}'" for w in feat_dict["_matched_suspicious_words"]])
        indicators.append({
            "type": "danger",
            "title": "Sensitive Keywords Found",
            "description": f"URL contains security-sensitive keyword(s): {words}."
        })

    if feat_dict["num_hyphens"] >= 3:
        indicators.append({
            "type": "warning",
            "title": "Excessive Hyphens",
            "description": f"Found {feat_dict['num_hyphens']} hyphens in URL, frequently used in brand typo-squatting."
        })

    if feat_dict["url_length"] > 75:
        indicators.append({
            "type": "warning",
            "title": "Long URL Length",
            "description": f"URL is {feat_dict['url_length']} characters long, often used to hide malicious domains."
        })

    if feat_dict["num_special_chars"] >= 3:
        indicators.append({
            "type": "warning",
            "title": "High Special Characters",
            "description": f"Found {feat_dict['num_special_chars']} special query characters (@, ?, =, &, etc.)."
        })

    if not indicators:
        indicators.append({
            "type": "success",
            "title": "Clean URL Structure",
            "description": "Standard domain structure, valid HTTPS, no suspicious keywords or abnormal character counts."
        })

    return indicators

if __name__ == "__main__":
    # Self-test feature extractor
    test_urls = [
        "https://www.google.com/search?q=cybersecurity",
        "http://192.168.1.10/paypal/login-verify-account.php",
        "https://secure-chase-update.xyz/signin?token=123"
    ]
    for test_url in test_urls:
        print(f"\nURL: {test_url}")
        feats = extract_features(test_url)
        print("Feature vector:", feats)
        indicators = get_suspicious_indicators(test_url)
        print("Indicators:", indicators)
