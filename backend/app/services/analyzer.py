"""
Analysis Service
Orchestrates: URL validation → Feature Extraction → Security Rules → ML → Risk Score → Response
"""

import re
import logging
from typing import Dict, Any
from urllib.parse import urlparse

from ..features.extractor import extract_features, features_to_vector, get_feature_names
from ..rules.heuristics import get_triggered_rules, compute_heuristic_score
from ..services.risk_scorer import (
    compute_risk_score,
    get_risk_level,
    get_classification,
    categorize_threats,
    build_explanation,
)
from ..models.loader import predict, is_model_loaded, get_feature_importances

logger = logging.getLogger(__name__)

MAX_URL_LENGTH = 2048


def validate_url(url: str) -> str:
    """
    Validate and normalize a URL.
    Returns normalized URL or raises ValueError.
    """
    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters.")

    # Add scheme if missing (for parsing only — we don't visit the URL)
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("URL does not have a valid hostname.")
    except Exception as e:
        raise ValueError(f"Invalid URL: {e}")

    return url


def analyze_url(raw_url: str, mutation_operator: str = None) -> Dict[str, Any]:
    """
    Full analysis pipeline for a submitted URL.
    Returns structured analysis result.
    """
    # 1. Validate
    try:
        url = validate_url(raw_url)
    except ValueError as e:
        return {"error": str(e), "url": raw_url}

    # 2. Extract features
    features = extract_features(url)
    feature_vector = features_to_vector(features)
    feature_names = get_feature_names()

    # 3. Run security rules
    triggered_rules = get_triggered_rules(url, features)
    heuristic_score = compute_heuristic_score(triggered_rules)

    # 4. ML prediction
    if is_model_loaded():
        try:
            label, ml_probability = predict(feature_vector)
        except Exception as e:
            logger.warning(f"ML prediction failed, falling back to heuristics: {e}")
            # Fallback: use heuristic score alone
            ml_probability = heuristic_score / 100.0
            label = 1 if ml_probability >= 0.5 else 0
    else:
        logger.warning("Model not loaded — using heuristic-only mode")
        ml_probability = min(heuristic_score / 100.0, 0.95)
        label = 1 if ml_probability >= 0.5 else 0

    # 5. Compute risk score
    risk_score = compute_risk_score(ml_probability, heuristic_score, features)
    risk_level = get_risk_level(risk_score)
    classification = get_classification(risk_score)

    # 6. Threat categorization
    threat_categories = categorize_threats(features, triggered_rules)

    # 7. Explanation
    explanation = build_explanation(risk_score, triggered_rules, features, ml_probability)

    # 8. Feature importance (top 10 for display)
    feature_importances = get_feature_importances()
    top_features = {}
    if feature_importances:
        sorted_fi = sorted(feature_importances.items(), key=lambda x: -x[1])[:10]
        top_features = {k: round(v, 4) for k, v in sorted_fi}

    # 9. Build risk factors for display (severity-ordered)
    risk_factors = []
    for severity in ("HIGH", "MEDIUM", "LOW"):
        for rule in triggered_rules:
            if rule["severity"] == severity:
                risk_factors.append({
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                })

    if mutation_operator:
        op_names = {
            "homoglyph": "Homoglyph Domain Substitution",
            "typosquat": "Typosquatting Domain Mutation",
            "hyphen": "Hyphen-Inserted Domain Mutation",
            "subdomain_padding": "Subdomain Padding Mutation",
            "keyword_insert": "Path Keyword Insertion Mutation",
            "percent_encode": "Percent-Encoding Path Mutation"
        }
        op_label = op_names.get(mutation_operator, f"{mutation_operator}")
        op_descriptions = {
            "homoglyph": "URL domain uses visually similar character substitutions (homoglyph attack).",
            "typosquat": "URL domain contains typosquatting character alterations (swapped, dropped, or duplicated letters).",
            "hyphen": "URL domain contains inserted hyphens to mimic legitimate domains.",
            "subdomain_padding": "URL uses padded subdomains (e.g. secure, login) to disguise the host.",
            "keyword_insert": "URL path contains inserted authentication or verification keywords.",
            "percent_encode": "URL path uses percent-encoding obfuscation to conceal characters."
        }
        desc = op_descriptions.get(mutation_operator, f"URL was created using the '{mutation_operator}' mutation operator.")
        
        mutation_factor = {
            "name": f"URL Mutation ({op_label})",
            "severity": "HIGH" if mutation_operator in ("homoglyph", "typosquat") else "MEDIUM",
            "description": desc
        }
        # Avoid duplicate if already present
        if not any(rf["name"] == mutation_factor["name"] or rf["name"] == "URL Mutation" for rf in risk_factors):
            if mutation_factor["severity"] == "HIGH":
                risk_factors.insert(0, mutation_factor)
            else:
                risk_factors.append(mutation_factor)

    # 10. Selected features for display (readable subset)
    display_features = {
        "url_length": features.get("url_length"),
        "hostname_length": features.get("hostname_length"),
        "num_dots": features.get("num_dots"),
        "num_hyphens": features.get("num_hyphens"),
        "num_subdomains": features.get("num_subdomains"),
        "url_entropy": features.get("url_entropy"),
        "is_https": bool(features.get("is_https")),
        "is_ip_address": bool(features.get("is_ip_address")),
        "has_punycode": bool(features.get("has_punycode")),
        "num_auth_keywords": features.get("num_auth_keywords"),
        "num_brand_tokens": features.get("num_brand_tokens"),
        "num_query_params": features.get("num_query_params"),
        "num_directories": features.get("num_directories"),
        "is_suspicious_tld": bool(features.get("is_suspicious_tld")),
    }

    return {
        "url": url,
        "original_url": raw_url,
        "classification": classification,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": round(ml_probability, 4),
        "threat_categories": threat_categories,
        "risk_factors": risk_factors,
        "features": display_features,
        "top_feature_importances": top_features,
        "explanation": explanation,
        "model_used": "XGBoost" if is_model_loaded() else "Heuristic-Only",
        "heuristic_score": heuristic_score,
    }
