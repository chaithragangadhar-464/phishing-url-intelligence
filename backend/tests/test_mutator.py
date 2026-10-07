"""
Unit and Integration Tests for Mutation Engine & Endpoint
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.main import app
from app.services.mutator import (
    generate_mutations,
    _parse_url_components,
    _mutate_homoglyphs,
    _mutate_typosquat,
    _mutate_hyphen,
    _mutate_subdomain_padding,
    _mutate_keyword_insert,
    _mutate_percent_encode,
)

client = TestClient(app)


class TestMutatorOperators:

    def test_parse_url_components(self):
        comp = _parse_url_components("https://user:pass@sub.example.com:8080/path/login?q=1#frag")
        assert comp["scheme"] == "https"
        assert comp["userinfo"] == "user:pass@"
        assert comp["hostname"] == "sub.example.com"
        assert comp["port_str"] == ":8080"
        assert comp["path"] == "/path/login"
        assert comp["query"] == "q=1"
        assert comp["domain"] == "example"
        assert comp["suffix"] == "com"

    def test_operator_homoglyph(self):
        comp = _parse_url_components("https://login.example.com/signin")
        mutations = _mutate_homoglyphs(comp)
        assert len(mutations) > 0
        ops = [m[1] for m in mutations]
        assert all(op == "homoglyph" for op in ops)

    def test_operator_typosquat(self):
        comp = _parse_url_components("https://example.com/signin")
        mutations = _mutate_typosquat(comp)
        assert len(mutations) > 0
        ops = [m[1] for m in mutations]
        assert all(op == "typosquat" for op in ops)

    def test_operator_hyphen(self):
        comp = _parse_url_components("https://example.com/signin")
        mutations = _mutate_hyphen(comp)
        assert len(mutations) > 0
        ops = [m[1] for m in mutations]
        assert all(op == "hyphen" for op in ops)

    def test_operator_subdomain_padding(self):
        comp = _parse_url_components("https://example.com/signin")
        mutations = _mutate_subdomain_padding(comp)
        assert len(mutations) == 4
        urls = [m[0] for m in mutations]
        assert any("secure.example.com" in u for u in urls)

    def test_operator_keyword_insert(self):
        comp = _parse_url_components("https://example.com/signin")
        mutations = _mutate_keyword_insert(comp)
        assert len(mutations) == 4
        urls = [m[0] for m in mutations]
        assert any("/login/signin" in u for u in urls)

    def test_operator_percent_encode(self):
        comp = _parse_url_components("https://example.com/signin")
        mutations = _mutate_percent_encode(comp)
        assert len(mutations) > 0
        urls = [m[0] for m in mutations]
        assert any("%" in u for u in urls)


class TestMutatorService:

    def test_generate_mutations_domain_host(self):
        result = generate_mutations("https://paypal-login.verify-account.example.com/signin")
        assert "original" in result
        assert "model_loaded" in result
        assert "variants" in result
        assert "summary" in result
        
        orig = result["original"]
        assert orig["url"].startswith("https://")
        assert "risk_score" in orig
        assert "ml_probability" in orig
        
        variants = result["variants"]
        assert len(variants) <= 25
        assert len(variants) > 0

        # Check variant schema fields
        first = variants[0]
        required_fields = [
            "url", "operator", "risk_score", "ml_probability",
            "classification", "delta_score", "delta_ml", "ml_dropped", "still_flagged"
        ]
        for f in required_fields:
            assert f in first, f"Missing variant field: {f}"

    def test_ip_host_input_only_path_operators(self):
        result = generate_mutations("http://192.168.10.5/secure/login.php")
        variants = result["variants"]
        operators = {v["operator"] for v in variants}
        # IP-host input must ONLY have keyword_insert and percent_encode
        assert operators.issubset({"keyword_insert", "percent_encode"})

    def test_url_with_port(self):
        result = generate_mutations("http://example.com:8080/login")
        assert result["original"]["risk_score"] >= 0
        assert len(result["variants"]) > 0
        assert any(":8080" in v["url"] for v in result["variants"])

    def test_url_with_at_sign(self):
        result = generate_mutations("http://user:pass@example.com/path")
        assert len(result["variants"]) > 0

    def test_25_variant_cap_and_deduplication(self):
        result = generate_mutations("https://very-long-domain-name-with-many-letters-example.com/deep/path/to/resource")
        variants = result["variants"]
        assert len(variants) <= 25
        urls = [v["url"].lower() for v in variants]
        assert len(urls) == len(set(urls))  # All unique
        assert result["original"]["url"].lower() not in set(urls)  # No original URL in variants

    def test_invalid_url_raises_value_error(self):
        with pytest.raises(ValueError):
            generate_mutations("")


class TestMutateAPIEndpoint:

    def test_post_mutate_success(self):
        response = client.post(
            "/api/mutate",
            json={"url": "https://paypal-login.verify-account.example.com/signin"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "original" in data
        assert "variants" in data
        assert "summary" in data

    def test_post_mutate_invalid_url_422(self):
        response = client.post(
            "/api/mutate",
            json={"url": ""}
        )
        assert response.status_code == 422

    def test_post_mutate_oversized_url_422(self):
        response = client.post(
            "/api/mutate",
            json={"url": "http://example.com/" + "a" * 3000}
        )
        assert response.status_code == 422
