"""
URL Feature Extractor
Extracts lexical, structural, and security-oriented features from a URL string.
This module is used by both the training pipeline and the inference backend.
NO external network requests are made here — pure string analysis only.
"""

import re
import math
import string
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

import tldextract


# ---------------------------------------------------------------------------
# Suspicious word lists (evidence-based, kept concise)
# ---------------------------------------------------------------------------
AUTH_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "logon", "log_in",
    "account", "verify", "verification", "authenticate", "auth",
    "password", "passwd", "credential", "credentials",
    "confirm", "secure", "security", "update", "billing",
}

PAYMENT_KEYWORDS = {
    "bank", "paypal", "payment", "checkout", "wallet",
    "credit", "debit", "card", "invoice", "purchase",
    "transaction", "fund", "transfer", "wire",
}

BRAND_KEYWORDS = {
    "google", "facebook", "microsoft", "apple", "amazon", "netflix",
    "paypal", "instagram", "twitter", "linkedin", "dropbox",
    "ebay", "adobe", "chase", "wellsfargo", "citibank",
    "bankofamerica", "outlook", "office365", "onedrive", "icloud",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # free TLDs heavily abused
    ".xyz", ".top", ".club", ".work", ".click",
    ".loan", ".download", ".racing", ".win", ".bid",
    ".stream", ".gdn", ".men", ".vip",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "short.link", "cutt.ly", "rb.gy", "tiny.cc",
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in freq.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def _is_ip_address(hostname: str) -> bool:
    """Check if hostname is an IPv4 or IPv6 address."""
    # IPv4
    ipv4_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if ipv4_pattern.match(hostname):
        parts = hostname.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6
    if hostname.startswith("[") and hostname.endswith("]"):
        return True
    return False


def _has_punycode(text: str) -> bool:
    """Detect punycode/IDN homograph encoding."""
    return "xn--" in text.lower()


def _count_special_chars(text: str, chars: str = "-_~%+&") -> int:
    return sum(text.count(c) for c in chars)


def _digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c.isdigit() for c in text) / len(text)


def _has_url_shortener(hostname: str) -> bool:
    return hostname.lower() in URL_SHORTENERS


def _count_brand_tokens(text: str) -> int:
    text_lower = text.lower()
    return sum(1 for b in BRAND_KEYWORDS if b in text_lower)


def _count_auth_keywords(text: str) -> int:
    text_lower = text.lower()
    return sum(1 for kw in AUTH_KEYWORDS if kw in text_lower)


def _count_payment_keywords(text: str) -> int:
    text_lower = text.lower()
    return sum(1 for kw in PAYMENT_KEYWORDS if kw in text_lower)


def _suspicious_tld(tld: str) -> bool:
    return f".{tld.lower()}" in SUSPICIOUS_TLDS


# ---------------------------------------------------------------------------
# Main feature extractor
# ---------------------------------------------------------------------------

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract all features from a URL string.
    Returns a flat dictionary of feature_name -> numeric_value.
    Safe to call with any string — will not raise on malformed URLs.
    """
    features: Dict[str, Any] = {}

    # ---- Basic parsing ----
    url = url.strip()
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("")

    ext = tldextract.extract(url)
    hostname = parsed.netloc or ""
    # Strip port from hostname
    hostname_no_port = hostname.split(":")[0] if ":" in hostname else hostname
    path = parsed.path or ""
    query = parsed.query or ""
    full_text = url.lower()

    # ---- Lexical features ----
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname_no_port)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_underscores"] = url.count("_")
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["num_special_chars"] = _count_special_chars(url)
    features["num_slashes"] = url.count("/")
    features["num_at_signs"] = url.count("@")
    features["num_ampersands"] = url.count("&")
    features["num_equal_signs"] = url.count("=")
    features["num_question_marks"] = url.count("?")
    features["num_percent"] = url.count("%")
    features["num_hash"] = url.count("#")

    features["url_entropy"] = _shannon_entropy(url)
    features["hostname_entropy"] = _shannon_entropy(hostname_no_port)
    features["path_entropy"] = _shannon_entropy(path)
    features["digit_ratio"] = _digit_ratio(url)

    # ---- Structural features ----
    features["is_https"] = 1 if parsed.scheme == "https" else 0
    features["is_ip_address"] = 1 if _is_ip_address(hostname_no_port) else 0
    features["has_port"] = 1 if (parsed.port is not None) else 0
    features["port_number"] = parsed.port if parsed.port else 0

    features["num_subdomains"] = len(ext.subdomain.split(".")) if ext.subdomain else 0
    features["subdomain_length"] = len(ext.subdomain) if ext.subdomain else 0
    features["domain_length"] = len(ext.domain) if ext.domain else 0
    features["tld_length"] = len(ext.suffix) if ext.suffix else 0

    features["num_directories"] = len([p for p in path.split("/") if p])
    features["num_query_params"] = len(parse_qs(query))

    features["has_double_slash"] = 1 if "//" in (path + query) else 0
    features["has_at_sign"] = 1 if "@" in url else 0
    features["has_encoded_chars"] = 1 if "%" in url else 0
    features["has_punycode"] = 1 if _has_punycode(url) else 0

    # ---- Security-oriented features ----
    features["is_suspicious_tld"] = 1 if _suspicious_tld(ext.suffix or "") else 0
    features["is_url_shortener"] = 1 if _has_url_shortener(ext.top_domain_under_public_suffix or "") else 0
    features["num_auth_keywords"] = _count_auth_keywords(full_text)
    features["num_payment_keywords"] = _count_payment_keywords(full_text)
    features["num_brand_tokens"] = _count_brand_tokens(full_text)

    # Domain-path token mismatch: brand in subdomain/path but not in registered domain
    brand_in_domain = any(b in (ext.domain or "").lower() for b in BRAND_KEYWORDS)
    brand_in_rest = any(
        b in (ext.subdomain + path + query).lower() for b in BRAND_KEYWORDS
    )
    features["brand_impersonation_indicator"] = 1 if (brand_in_rest and not brand_in_domain) else 0

    # Suspicious domain patterns
    features["domain_has_hyphen"] = 1 if "-" in (ext.domain or "") else 0
    features["domain_has_digit"] = 1 if any(c.isdigit() for c in (ext.domain or "")) else 0

    # Hex encoding in URL
    features["has_hex_chars"] = 1 if re.search(r"%[0-9a-fA-F]{2}", url) else 0

    # Excessive directory depth (>= 5 levels is suspicious)
    features["deep_path"] = 1 if features["num_directories"] >= 5 else 0

    # Very long hostname (>= 30 chars)
    features["long_hostname"] = 1 if features["hostname_length"] >= 30 else 0

    return features


def get_feature_names() -> list:
    """Return ordered list of feature names (matches extract_features output)."""
    # Extract from a dummy URL to get consistent ordering
    dummy = extract_features("http://example.com/path?q=1")
    return list(dummy.keys())


def features_to_vector(features: Dict[str, Any]) -> list:
    """Convert features dict to ordered numeric list for ML inference."""
    return [float(v) for v in features.values()]
