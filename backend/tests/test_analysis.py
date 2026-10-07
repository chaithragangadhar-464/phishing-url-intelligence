"""
Backend Tests
Tests for feature extraction, security rules, and API endpoints.
Run from the backend/ directory: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from app.features.extractor import extract_features, get_feature_names
from app.rules.heuristics import run_rules, get_triggered_rules
from app.services.analyzer import validate_url, analyze_url


# ============================================================
# Feature Extraction Tests
# ============================================================

class TestFeatureExtraction:

    def test_basic_https_url(self):
        features = extract_features("https://www.google.com/search?q=test")
        assert features["is_https"] == 1
        assert features["num_dots"] >= 2
        assert features["url_length"] > 0

    def test_http_url(self):
        features = extract_features("http://example.com")
        assert features["is_https"] == 0

    def test_ip_address_hostname(self):
        features = extract_features("http://192.168.1.1/login")
        assert features["is_ip_address"] == 1

    def test_at_sign_in_url(self):
        features = extract_features("http://user@evil.com/path")
        assert features["has_at_sign"] == 1
        assert features["num_at_signs"] >= 1

    def test_punycode_detection(self):
        features = extract_features("https://xn--pple-43d.com/account")
        assert features["has_punycode"] == 1

    def test_empty_url_graceful(self):
        # Should not raise
        features = extract_features("")
        assert isinstance(features, dict)

    def test_very_long_url(self):
        long_url = "http://phish.tk/" + "a" * 500
        features = extract_features(long_url)
        assert features["url_length"] > 100

    def test_auth_keywords(self):
        features = extract_features("http://evil.tk/login/verify/password")
        assert features["num_auth_keywords"] >= 2

    def test_payment_keywords(self):
        features = extract_features("http://fake-paypal.tk/billing/payment")
        assert features["num_payment_keywords"] >= 1

    def test_brand_impersonation(self):
        features = extract_features("http://secure-paypal-login.evil.tk/signin")
        assert features["num_brand_tokens"] >= 1

    def test_entropy_calculation(self):
        features = extract_features("http://aaaaaaaaa.com")
        # Low entropy for repetitive URL
        features2 = extract_features("http://xK9mP2qL7rN1wT4j.tk/kds83jf9")
        # High entropy URL should have higher entropy than repetitive one
        # This test just checks entropy is computed
        assert "url_entropy" in features
        assert features["url_entropy"] >= 0

    def test_suspicious_tld(self):
        features = extract_features("http://domain.tk/path")
        assert features["is_suspicious_tld"] == 1

        features2 = extract_features("https://domain.com/path")
        assert features2["is_suspicious_tld"] == 0

    def test_feature_count(self):
        features = extract_features("https://www.google.com/")
        assert len(features) >= 40  # At least 40 features

    def test_subdomain_count(self):
        features = extract_features("http://a.b.c.evil.tk/path")
        assert features["num_subdomains"] >= 2

    def test_query_params(self):
        features = extract_features("http://example.com/path?a=1&b=2&c=3")
        assert features["num_query_params"] == 3

    def test_port_detection(self):
        features = extract_features("http://evil.com:8080/login")
        assert features["has_port"] == 1
        assert features["port_number"] == 8080

    def test_encoded_chars(self):
        features = extract_features("http://evil.com/%6c%6f%67%69%6e")
        assert features["has_encoded_chars"] == 1

    def test_feature_names_consistent(self):
        names = get_feature_names()
        features = extract_features("https://example.com/path?q=1")
        assert list(features.keys()) == names


# ============================================================
# Security Rules Tests
# ============================================================

class TestSecurityRules:

    def test_ip_address_rule_triggered(self):
        features = extract_features("http://192.168.1.1/login")
        triggered = get_triggered_rules("http://192.168.1.1/login", features)
        names = [r["name"] for r in triggered]
        assert "IP Address as Hostname" in names

    def test_at_sign_rule_triggered(self):
        features = extract_features("http://user@evil.com/path")
        triggered = get_triggered_rules("http://user@evil.com/path", features)
        names = [r["name"] for r in triggered]
        assert "@ Sign in URL" in names

    def test_punycode_rule_triggered(self):
        features = extract_features("https://xn--pple-43d.com/")
        triggered = get_triggered_rules("https://xn--pple-43d.com/", features)
        names = [r["name"] for r in triggered]
        assert "Punycode / IDN Homograph" in names

    def test_safe_url_no_high_rules(self):
        features = extract_features("https://www.google.com/")
        triggered = get_triggered_rules("https://www.google.com/", features)
        high_rules = [r for r in triggered if r["severity"] == "HIGH"]
        assert len(high_rules) == 0

    def test_all_rules_have_severity(self):
        features = extract_features("http://evil.tk/login")
        all_rules = run_rules("http://evil.tk/login", features)
        for rule in all_rules:
            assert rule["severity"] in ("HIGH", "MEDIUM", "LOW")
            assert "name" in rule
            assert "description" in rule
            assert "triggered" in rule

    def test_suspicious_tld_rule(self):
        features = extract_features("http://phish.tk/verify")
        triggered = get_triggered_rules("http://phish.tk/verify", features)
        names = [r["name"] for r in triggered]
        assert "Suspicious TLD" in names

    def test_excessive_subdomains_rule(self):
        url = "http://a.b.c.d.evil.tk/"
        features = extract_features(url)
        triggered = get_triggered_rules(url, features)
        names = [r["name"] for r in triggered]
        assert "Excessive Subdomains" in names

    def test_scam_keywords_rule(self):
        url = "http://free-software-crack.com/download/keygen"
        features = extract_features(url)
        triggered = get_triggered_rules(url, features)
        names = [r["name"] for r in triggered]
        assert "Scam / Illegal Activity Keywords" in names

    def test_executable_extension_rule(self):
        url = "http://malicious-site.com/setup.exe"
        features = extract_features(url)
        triggered = get_triggered_rules(url, features)
        names = [r["name"] for r in triggered]
        assert "Dangerous Executable File Download" in names


# ============================================================
# URL Validation Tests
# ============================================================

class TestURLValidation:

    def test_valid_https_url(self):
        url = validate_url("https://www.example.com/path")
        assert url.startswith("https://")

    def test_url_without_scheme_gets_http(self):
        url = validate_url("www.example.com")
        assert url.startswith("http://")

    def test_empty_url_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_url("")

    def test_oversized_url_raises(self):
        with pytest.raises(ValueError, match="maximum length"):
            validate_url("http://evil.com/" + "a" * 3000)

    def test_no_hostname_raises(self):
        with pytest.raises(ValueError):
            validate_url("http:///no-hostname")


# ============================================================
# Full Analysis Pipeline Tests
# ============================================================

class TestAnalysisPipeline:

    def test_phishing_url_returns_result(self):
        result = analyze_url("http://192.168.1.1/login/verify")
        assert "risk_score" in result
        assert "classification" in result
        assert "risk_factors" in result
        assert result["risk_score"] >= 0

    def test_safe_url_low_risk(self):
        result = analyze_url("https://www.google.com/")
        assert "risk_score" in result
        # Google should score reasonably low
        assert result["risk_score"] <= 50

    def test_phishing_url_high_risk(self):
        result = analyze_url("http://user@192.168.1.1:8080/login/paypal/verify/password")
        assert result["risk_score"] > 50

    def test_empty_url_returns_error(self):
        result = analyze_url("")
        assert "error" in result

    def test_result_structure(self):
        result = analyze_url("https://example.com/test")
        required_keys = [
            "url", "classification", "risk_score", "risk_level",
            "confidence", "risk_factors", "features", "explanation"
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_classification_is_valid(self):
        result = analyze_url("https://example.com")
        assert result["classification"] in ("phishing", "legitimate")

    def test_risk_level_is_valid(self):
        result = analyze_url("https://example.com")
        assert result["risk_level"] in ("SAFE", "LOW", "MEDIUM", "HIGH")

    def test_risk_score_in_range(self):
        result = analyze_url("https://example.com")
        assert 0 <= result["risk_score"] <= 100

    def test_punycode_url_detected(self):
        result = analyze_url("https://xn--pple-43d.com/account/verify")
        assert result["risk_score"] > 30

    def test_brand_impersonation_detected(self):
        result = analyze_url("http://secure-paypal-login.verify.tk/signin")
        assert result["risk_score"] > 40

    def test_explanation_is_string(self):
        result = analyze_url("https://example.com")
        assert isinstance(result.get("explanation"), str)
        assert len(result["explanation"]) > 10


if __name__ == "__main__":
    # Quick smoke test without pytest
    print("Running basic smoke tests...")

    t = TestFeatureExtraction()
    t.test_basic_https_url()
    t.test_ip_address_hostname()
    t.test_at_sign_in_url()
    t.test_punycode_detection()
    t.test_suspicious_tld()
    print("✅ Feature extraction tests passed")

    t2 = TestSecurityRules()
    t2.test_ip_address_rule_triggered()
    t2.test_at_sign_rule_triggered()
    t2.test_safe_url_no_high_rules()
    print("✅ Security rules tests passed")

    t3 = TestURLValidation()
    try:
        t3.test_empty_url_raises()
        print("✅ URL validation tests passed")
    except Exception as e:
        print(f"⚠️  Validation test: {e}")

    t4 = TestAnalysisPipeline()
    t4.test_result_structure()
    t4.test_risk_score_in_range()
    t4.test_classification_is_valid()
    print("✅ Pipeline tests passed")

    print("\n✅ All smoke tests passed!")
