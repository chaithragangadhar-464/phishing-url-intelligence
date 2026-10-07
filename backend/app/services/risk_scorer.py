"""
Risk Scoring & Threat Categorization
Combines ML probability with heuristic evidence to produce a final risk score and threat categories.
"""

from typing import Dict, List, Any


# ---------------------------------------------------------------------------
# Threat categories — only assigned when evidence supports them
# ---------------------------------------------------------------------------

def categorize_threats(features: Dict, triggered_rules: List[Dict]) -> List[str]:
    """
    Derive threat categories from triggered rules and features.
    Only assigns a category when there is concrete evidence.
    """
    categories = []
    triggered_names = {r["name"] for r in triggered_rules if r["triggered"]}

    if "Brand Impersonation" in triggered_names:
        categories.append("Brand Impersonation")

    if "Authentication Keywords" in triggered_names or "Payment / Financial Keywords" in triggered_names:
        if "Brand Impersonation" in triggered_names or "IP Address as Hostname" in triggered_names:
            categories.append("Credential Harvesting")
        else:
            categories.append("Social Engineering")

    if "Punycode / IDN Homograph" in triggered_names:
        categories.append("Homograph Attack")

    if "@ Sign in URL" in triggered_names or "URL Encoding Obfuscation" in triggered_names:
        categories.append("URL Obfuscation")

    if "Excessive Subdomains" in triggered_names:
        categories.append("Suspicious Domain Structure")

    if "Payment / Financial Keywords" in triggered_names and "HTTP (Unencrypted) with Sensitive Keywords" in triggered_names:
        categories.append("Payment Targeting")

    if "Dangerous Executable File Download" in triggered_names:
        categories.append("Malware Distribution")

    if "Scam / Illegal Activity Keywords" in triggered_names:
        categories.append("Illegal Content / Scam")

    if features.get("num_brand_tokens", 0) > 0 and features.get("brand_impersonation_indicator", 0) == 1:
        if "Brand Impersonation" not in categories:
            categories.append("Brand Impersonation")

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for c in categories:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


# ---------------------------------------------------------------------------
# Risk score computation
# ---------------------------------------------------------------------------

def compute_risk_score(
    ml_probability: float,
    heuristic_score: float,
    features: Dict,
) -> int:
    """
    Compute final risk score (0–100).

    Methodology:
    - ML probability contributes 60% of the score
    - Heuristic score contributes 40%
    - Capped at 100

    This blended approach means:
    - A URL with high ML probability but few heuristics is still penalized
    - A URL with multiple rule triggers but low ML probability is still risky
    """
    ml_contribution = ml_probability * 60        # 0–60
    heuristic_contribution = (heuristic_score / 100) * 40  # 0–40
    raw_score = ml_contribution + heuristic_contribution

    # Bonus adjustments for high-severity indicators
    if features.get("is_ip_address", 0) == 1:
        raw_score = min(raw_score + 8, 100)
    if features.get("has_punycode", 0) == 1:
        raw_score = min(raw_score + 8, 100)
    if features.get("has_at_sign", 0) == 1:
        raw_score = min(raw_score + 5, 100)
    if features.get("brand_domain_mutation", 0) == 1:
        raw_score = min(raw_score + 35, 100)

    # Scam and executable extension boosts
    scam_count = features.get("num_scam_keywords", 0)
    if scam_count >= 2:
        raw_score = min(raw_score + 35, 100)
    elif scam_count == 1:
        raw_score = min(raw_score + 25, 100)

    if features.get("has_executable_ext", 0) == 1:
        raw_score = min(raw_score + 25, 100)

    return int(min(round(raw_score), 100))


# ---------------------------------------------------------------------------
# Risk level label
# ---------------------------------------------------------------------------

def get_risk_level(risk_score: int) -> str:
    if risk_score >= 75:
        return "HIGH"
    elif risk_score >= 45:
        return "MEDIUM"
    elif risk_score >= 20:
        return "LOW"
    else:
        return "SAFE"


def get_classification(risk_score: int) -> str:
    if risk_score >= 50:
        return "phishing"
    return "legitimate"


# ---------------------------------------------------------------------------
# Human-readable explanation
# ---------------------------------------------------------------------------

def build_explanation(
    risk_score: int,
    triggered_rules: List[Dict],
    features: Dict,
    ml_probability: float,
) -> str:
    """Generate a plain-English summary for a non-technical user."""
    level = get_risk_level(risk_score)
    classification = get_classification(risk_score)

    high_rules = [r["name"] for r in triggered_rules if r["severity"] == "HIGH"]
    med_rules  = [r["name"] for r in triggered_rules if r["severity"] == "MEDIUM"]

    if classification == "phishing":
        if high_rules:
            detail = f"Critical indicators include: {', '.join(high_rules[:3])}."
        elif med_rules:
            detail = f"Multiple suspicious patterns were detected: {', '.join(med_rules[:3])}."
        else:
            detail = "The URL's statistical properties closely match known phishing patterns."
        return (
            f"⚠️ This URL appears suspicious with a risk score of {risk_score}/100. "
            f"{detail} "
            f"The machine-learning model assigned a {ml_probability*100:.0f}% phishing probability. "
            "Do not enter personal information on this site."
        )
    else:
        if triggered_rules:
            note = f"Minor concerns noted: {', '.join(r['name'] for r in triggered_rules[:2])}."
        else:
            note = "No suspicious indicators were detected."
        return (
            f"✅ This URL appears relatively safe with a risk score of {risk_score}/100. "
            f"{note} "
            f"The machine-learning model assigned a {ml_probability*100:.0f}% phishing probability. "
            "Standard caution is always advisable."
        )
