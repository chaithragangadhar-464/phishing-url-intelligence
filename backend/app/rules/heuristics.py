"""
Security Heuristics Rule Engine
Deterministic cybersecurity rules that produce evidence-based flags.
Each rule returns a dict with: name, severity, description, triggered (bool).
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any
import tldextract


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

class RuleResult:
    def __init__(self, name: str, severity: str, description: str, triggered: bool):
        self.name = name
        self.severity = severity          # "HIGH", "MEDIUM", "LOW"
        self.description = description
        self.triggered = triggered

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "triggered": self.triggered,
        }


def _rule_ip_hostname(url: str, features: Dict) -> RuleResult:
    triggered = features.get("is_ip_address", 0) == 1
    return RuleResult(
        name="IP Address as Hostname",
        severity="HIGH",
        description="URL uses a raw IP address instead of a domain name — common in phishing to avoid DNS traceability.",
        triggered=triggered,
    )


def _rule_at_sign(url: str, features: Dict) -> RuleResult:
    triggered = features.get("has_at_sign", 0) == 1
    return RuleResult(
        name="@ Sign in URL",
        severity="HIGH",
        description="The '@' character in a URL redirects the browser; content before @ is ignored. Used to disguise the real destination.",
        triggered=triggered,
    )


def _rule_punycode(url: str, features: Dict) -> RuleResult:
    triggered = features.get("has_punycode", 0) == 1
    return RuleResult(
        name="Punycode / IDN Homograph",
        severity="HIGH",
        description="URL contains punycode (xn--) encoding, which can render visually identical to legitimate domains using different Unicode characters.",
        triggered=triggered,
    )


def _rule_suspicious_tld(url: str, features: Dict) -> RuleResult:
    triggered = features.get("is_suspicious_tld", 0) == 1
    return RuleResult(
        name="Suspicious TLD",
        severity="MEDIUM",
        description="URL uses a TLD (e.g. .tk, .ml, .xyz) heavily associated with free/malicious domain registrations.",
        triggered=triggered,
    )


def _rule_brand_impersonation(url: str, features: Dict) -> RuleResult:
    triggered = features.get("brand_impersonation_indicator", 0) == 1
    return RuleResult(
        name="Brand Impersonation",
        severity="HIGH",
        description="URL contains a well-known brand name in the subdomain or path, but the registered domain does not match — a common credential-harvesting technique.",
        triggered=triggered,
    )


def _rule_excessive_subdomains(url: str, features: Dict) -> RuleResult:
    triggered = features.get("num_subdomains", 0) >= 3
    return RuleResult(
        name="Excessive Subdomains",
        severity="MEDIUM",
        description=f"URL has {features.get('num_subdomains', 0)} subdomain levels — attackers stack subdomains to make URLs appear legitimate.",
        triggered=triggered,
    )


def _rule_auth_keywords(url: str, features: Dict) -> RuleResult:
    count = features.get("num_auth_keywords", 0)
    triggered = count >= 1
    return RuleResult(
        name="Authentication Keywords",
        severity="MEDIUM",
        description=f"URL contains {count} authentication-related keyword(s) (e.g. 'login', 'verify', 'password') — typical in credential-harvesting pages.",
        triggered=triggered,
    )


def _rule_payment_keywords(url: str, features: Dict) -> RuleResult:
    count = features.get("num_payment_keywords", 0)
    triggered = count >= 1
    return RuleResult(
        name="Payment / Financial Keywords",
        severity="MEDIUM",
        description=f"URL contains {count} payment-related keyword(s) (e.g. 'bank', 'paypal', 'billing') — common in financial phishing.",
        triggered=triggered,
    )


def _rule_url_shortener(url: str, features: Dict) -> RuleResult:
    triggered = features.get("is_url_shortener", 0) == 1
    return RuleResult(
        name="URL Shortener Service",
        severity="MEDIUM",
        description="URL uses a known shortening service that hides the real destination.",
        triggered=triggered,
    )


def _rule_excessive_length(url: str, features: Dict) -> RuleResult:
    length = features.get("url_length", 0)
    triggered = length > 100
    return RuleResult(
        name="Excessive URL Length",
        severity="LOW",
        description=f"URL is {length} characters long — unusually long URLs often contain obfuscation or redirect chains.",
        triggered=triggered,
    )


def _rule_high_entropy(url: str, features: Dict) -> RuleResult:
    entropy = features.get("url_entropy", 0)
    triggered = entropy > 4.5
    return RuleResult(
        name="High URL Entropy",
        severity="LOW",
        description=f"URL entropy is {entropy:.2f} (threshold 4.5) — high entropy suggests obfuscated or randomly-generated content.",
        triggered=triggered,
    )


def _rule_encoded_chars(url: str, features: Dict) -> RuleResult:
    triggered = features.get("has_encoded_chars", 0) == 1 and features.get("num_percent", 0) >= 3
    return RuleResult(
        name="URL Encoding Obfuscation",
        severity="LOW",
        description=f"URL contains {features.get('num_percent', 0)} percent-encoded characters — may be used to evade filters.",
        triggered=triggered,
    )


def _rule_double_slash(url: str, features: Dict) -> RuleResult:
    triggered = features.get("has_double_slash", 0) == 1
    return RuleResult(
        name="Double Slash in Path",
        severity="LOW",
        description="URL path contains '//' — sometimes used in redirect manipulation.",
        triggered=triggered,
    )


def _rule_domain_has_hyphen(url: str, features: Dict) -> RuleResult:
    triggered = features.get("domain_has_hyphen", 0) == 1
    return RuleResult(
        name="Hyphen in Domain",
        severity="LOW",
        description="Registered domain contains a hyphen — slightly elevated in phishing domains that try to mimic legitimate ones (e.g. 'secure-paypal.com').",
        triggered=triggered,
    )


def _rule_url_mutation(url: str, features: Dict) -> RuleResult:
    has_homoglyph_puny = features.get("has_punycode", 0) == 1
    has_hyphen_brand = (features.get("domain_has_hyphen", 0) == 1 and features.get("num_brand_tokens", 0) > 0)
    has_encoded_path = (features.get("has_encoded_chars", 0) == 1 and features.get("num_auth_keywords", 0) >= 1)
    has_brand_mutation = features.get("brand_domain_mutation", 0) == 1
    has_digit_brand = (features.get("domain_has_digit", 0) == 1 and features.get("num_brand_tokens", 0) > 0)
    
    triggered = has_homoglyph_puny or has_hyphen_brand or has_encoded_path or has_brand_mutation or has_digit_brand
    severity = "HIGH" if (has_brand_mutation or has_homoglyph_puny) else "MEDIUM"
    return RuleResult(
        name="URL Mutation",
        severity=severity,
        description="URL exhibits brand typosquatting, character addition, or domain mutation patterns common in spoofing attacks.",
        triggered=triggered,
    )


def _rule_non_standard_port(url: str, features: Dict) -> RuleResult:
    port = features.get("port_number", 0)
    triggered = port not in (0, 80, 443, 8080, 8443) and port > 0
    return RuleResult(
        name="Non-Standard Port",
        severity="MEDIUM",
        description=f"URL specifies port {port}, which is unusual for a legitimate web service.",
        triggered=triggered,
    )


def _rule_http_only(url: str, features: Dict) -> RuleResult:
    triggered = features.get("is_https", 0) == 0 and features.get("num_auth_keywords", 0) >= 1
    return RuleResult(
        name="HTTP (Unencrypted) with Sensitive Keywords",
        severity="HIGH",
        description="URL uses HTTP (not HTTPS) and contains authentication or payment keywords — credentials would be transmitted in plaintext.",
        triggered=triggered,
    )


def _rule_scam_keywords(url: str, features: Dict) -> RuleResult:
    count = features.get("num_scam_keywords", 0)
    triggered = count >= 1
    severity = "HIGH" if count >= 2 else "MEDIUM"
    return RuleResult(
        name="Scam / Illegal Activity Keywords",
        severity=severity,
        description=f"URL contains {count} keyword(s) associated with illegal activity, scams, malware or piracy (e.g. 'crack', 'torrent', 'airdrop', 'stealer', 'hack').",
        triggered=triggered,
    )


def _rule_executable_extension(url: str, features: Dict) -> RuleResult:
    triggered = features.get("has_executable_ext", 0) == 1
    return RuleResult(
        name="Dangerous Executable File Download",
        severity="HIGH",
        description="URL targets an executable file extension (.exe, .apk, .bat, .vbs, .msi, .iso) — high risk of malware or trojan distribution.",
        triggered=triggered,
    )


def _rule_unencrypted_http(url: str, features: Dict) -> RuleResult:
    triggered = features.get("is_https", 0) == 0
    return RuleResult(
        name="Unencrypted HTTP Protocol",
        severity="LOW",
        description="URL uses plain HTTP without SSL/TLS encryption.",
        triggered=triggered,
    )


# All rules in priority order
ALL_RULES = [
    _rule_ip_hostname,
    _rule_at_sign,
    _rule_punycode,
    _rule_brand_impersonation,
    _rule_executable_extension,
    _rule_scam_keywords,
    _rule_http_only,
    _rule_suspicious_tld,
    _rule_excessive_subdomains,
    _rule_auth_keywords,
    _rule_payment_keywords,
    _rule_url_shortener,
    _rule_non_standard_port,
    _rule_unencrypted_http,
    _rule_excessive_length,
    _rule_high_entropy,
    _rule_encoded_chars,
    _rule_double_slash,
    _rule_domain_has_hyphen,
    _rule_url_mutation,
]


def run_rules(url: str, features: Dict) -> List[Dict]:
    """Run all security rules and return list of triggered rule dicts."""
    results = []
    for rule_fn in ALL_RULES:
        result = rule_fn(url, features)
        results.append(result.to_dict())
    return results


def get_triggered_rules(url: str, features: Dict) -> List[Dict]:
    """Return only the rules that were triggered."""
    return [r for r in run_rules(url, features) if r["triggered"]]


def compute_heuristic_score(triggered_rules: List[Dict]) -> float:
    """
    Compute a 0-100 heuristic contribution score from triggered rules.
    HIGH rules contribute more weight.
    """
    severity_weights = {"HIGH": 25, "MEDIUM": 15, "LOW": 5}
    score = sum(severity_weights.get(r["severity"], 5) for r in triggered_rules)
    return min(score, 100)
