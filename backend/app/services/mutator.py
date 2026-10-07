"""
URL Mutation Engine
Generates deterministic, ASCII-safe string mutations of a target URL
and scores them against the analysis pipeline.
"""

import re
from urllib.parse import urlparse, urlunparse
from typing import List, Dict, Any, Tuple
import tldextract

from app.services.analyzer import analyze_url, validate_url
from app.features.extractor import _is_ip_address


def _parse_url_components(url: str) -> Dict[str, str]:
    """Parse URL into scheme, userinfo, hostname, port, path, query, fragment."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    netloc = parsed.netloc or ""
    
    userinfo = ""
    host_port = netloc
    if "@" in netloc:
        userinfo, host_port = netloc.rsplit("@", 1)
        userinfo += "@"
        
    hostname = host_port
    port_str = ""
    if ":" in host_port and not (host_port.startswith("[") and host_port.endswith("]")):
        # Check if port is after last colon
        parts = host_port.rsplit(":", 1)
        if parts[1].isdigit():
            hostname, port_str = parts[0], ":" + parts[1]

    ext = tldextract.extract(url)
    
    return {
        "scheme": parsed.scheme or "http",
        "userinfo": userinfo,
        "hostname": hostname,
        "port_str": port_str,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
        "subdomain": ext.subdomain or "",
        "domain": ext.domain or "",
        "suffix": ext.suffix or "",
    }


def _rebuild_url(comp: Dict[str, str], new_domain: str = None, new_subdomain: str = None, new_path: str = None) -> str:
    """Rebuild full URL string from components with optional overrides."""
    subdomain = comp["subdomain"] if new_subdomain is None else new_subdomain
    domain = comp["domain"] if new_domain is None else new_domain
    suffix = comp["suffix"]
    
    if domain:
        host = f"{subdomain}.{domain}" if subdomain else domain
        if suffix:
            host = f"{host}.{suffix}"
    else:
        host = comp["hostname"]
        
    netloc = f"{comp['userinfo']}{host}{comp['port_str']}"
    path = comp["path"] if new_path is None else new_path
    
    return urlunparse((
        comp["scheme"],
        netloc,
        path,
        "",
        comp["query"],
        comp["fragment"]
    ))


def _mutate_homoglyphs(comp: Dict[str, str]) -> List[Tuple[str, str]]:
    """Operator 1: Homoglyph substitutions in registered domain label."""
    domain = comp["domain"]
    if not domain:
        return []
    
    replacements = [("l", "1"), ("o", "0"), ("rn", "m"), ("i", "l")]
    results = []
    
    for old, new in replacements:
        if old in domain:
            mutated_domain = domain.replace(old, new, 1)
            if mutated_domain != domain:
                new_url = _rebuild_url(comp, new_domain=mutated_domain)
                results.append((new_url, "homoglyph"))
                
    return results


def _mutate_typosquat(comp: Dict[str, str]) -> List[Tuple[str, str]]:
    """Operator 2: Drop letter, duplicate letter, swap adjacent letters."""
    domain = comp["domain"]
    if not domain or len(domain) < 2:
        return []
    
    results = []
    
    # 1. Swap adjacent letters (first pair available)
    for i in range(len(domain) - 1):
        if domain[i] != domain[i+1]:
            swapped = domain[:i] + domain[i+1] + domain[i] + domain[i+2:]
            results.append((_rebuild_url(comp, new_domain=swapped), "typosquat"))
            break
            
    # 2. Drop a letter (from middle or end)
    mid_idx = len(domain) // 2
    dropped = domain[:mid_idx] + domain[mid_idx+1:]
    if dropped:
        results.append((_rebuild_url(comp, new_domain=dropped), "typosquat"))
        
    # 3. Duplicate a letter
    dup_idx = len(domain) // 2
    duplicated = domain[:dup_idx] + domain[dup_idx] + domain[dup_idx:]
    results.append((_rebuild_url(comp, new_domain=duplicated), "typosquat"))
    
    # 4. Drop last letter
    if len(domain) > 3:
        dropped_last = domain[:-1]
        results.append((_rebuild_url(comp, new_domain=dropped_last), "typosquat"))
        
    return results


def _mutate_hyphen(comp: Dict[str, str]) -> List[Tuple[str, str]]:
    """Operator 3: Insert hyphen inside registered-domain label."""
    domain = comp["domain"]
    if not domain or len(domain) < 3:
        return []
    
    results = []
    positions = [len(domain) // 2, 2, len(domain) - 2]
    for pos in positions:
        if 1 <= pos < len(domain):
            hyphenated = domain[:pos] + "-" + domain[pos:]
            results.append((_rebuild_url(comp, new_domain=hyphenated), "hyphen"))
            
    return results


def _mutate_subdomain_padding(comp: Dict[str, str]) -> List[Tuple[str, str]]:
    """Operator 4: Prefix hostname with secure. / login. / account. / verify."""
    prefixes = ["secure", "login", "account", "verify"]
    results = []
    
    curr_sub = comp["subdomain"]
    for p in prefixes:
        new_sub = f"{p}.{curr_sub}" if curr_sub else p
        results.append((_rebuild_url(comp, new_subdomain=new_sub), "subdomain_padding"))
        
    return results


def _mutate_keyword_insert(comp: Dict[str, str]) -> List[Tuple[str, str]]:
    """Operator 5: Add login, verify, update, secure to path."""
    keywords = ["login", "verify", "update", "secure"]
    results = []
    curr_path = comp["path"]
    
    if not curr_path or curr_path == "/":
        for kw in keywords:
            results.append((_rebuild_url(comp, new_path=f"/{kw}"), "keyword_insert"))
    else:
        # Prepend keyword segment
        for kw in keywords:
            clean_path = curr_path if curr_path.startswith("/") else "/" + curr_path
            results.append((_rebuild_url(comp, new_path=f"/{kw}{clean_path}"), "keyword_insert"))
            
    return results


def _mutate_percent_encode(comp: Dict[str, str]) -> List[Tuple[str, str]]:
    """Operator 6: Percent-encode 2-3 letters in path."""
    curr_path = comp["path"]
    if not curr_path or curr_path == "/":
        target = "/login"
    else:
        target = curr_path
        
    results = []
    # Find positions of ASCII letters in target
    alpha_indices = [i for i, ch in enumerate(target) if ch.isalpha()]
    
    if not alpha_indices:
        # Fallback to encoding /login
        target = "/login"
        alpha_indices = [i for i, ch in enumerate(target) if ch.isalpha()]

    # Variant 1: Encode first 2 letters
    if len(alpha_indices) >= 2:
        chars = list(target)
        for idx in alpha_indices[:2]:
            chars[idx] = f"%{ord(chars[idx]):02X}"
        results.append((_rebuild_url(comp, new_path="".join(chars)), "percent_encode"))

    # Variant 2: Encode 2 letters from middle
    if len(alpha_indices) >= 3:
        chars = list(target)
        mid = len(alpha_indices) // 2
        for idx in alpha_indices[mid:mid+2]:
            chars[idx] = f"%{ord(chars[idx]):02X}"
        results.append((_rebuild_url(comp, new_path="".join(chars)), "percent_encode"))

    # Variant 3: Encode last 2 letters
    if len(alpha_indices) >= 2:
        chars = list(target)
        for idx in alpha_indices[-2:]:
            chars[idx] = f"%{ord(chars[idx]):02X}"
        results.append((_rebuild_url(comp, new_path="".join(chars)), "percent_encode"))

    # Variant 4: Encode 3 letters
    if len(alpha_indices) >= 3:
        chars = list(target)
        for idx in alpha_indices[:3]:
            chars[idx] = f"%{ord(chars[idx]):02X}"
        results.append((_rebuild_url(comp, new_path="".join(chars)), "percent_encode"))

    return results


def generate_mutations(url: str) -> Dict[str, Any]:
    """
    Generate mutations, score each with analyze_url(), and build response dict.
    Max 25 variants total.
    """
    # 1. Validate original URL
    norm_url = validate_url(url)
    orig_result = analyze_url(norm_url)
    
    if "error" in orig_result:
        raise ValueError(orig_result["error"])
        
    orig_risk_score = orig_result.get("risk_score", 0)
    orig_classification = orig_result.get("classification", "legitimate")
    orig_ml_prob = round(orig_result.get("confidence", 0.0), 4)
    model_used = orig_result.get("model_used", "Heuristic-Only")
    
    original_summary = {
        "url": norm_url,
        "risk_score": orig_risk_score,
        "classification": orig_classification,
        "ml_probability": orig_ml_prob,
        "model_used": model_used
    }
    
    # 2. Parse URL components
    comp = _parse_url_components(norm_url)
    is_ip = _is_ip_address(comp["hostname"])
    
    # 3. Generate raw variants by operator
    raw_variants: List[Tuple[str, str]] = []
    
    if is_ip:
        # IP-address hosts: ONLY apply path-based operators (5 & 6)
        raw_variants.extend(_mutate_keyword_insert(comp))
        raw_variants.extend(_mutate_percent_encode(comp))
    else:
        raw_variants.extend(_mutate_homoglyphs(comp))
        raw_variants.extend(_mutate_typosquat(comp))
        raw_variants.extend(_mutate_hyphen(comp))
        raw_variants.extend(_mutate_subdomain_padding(comp))
        raw_variants.extend(_mutate_keyword_insert(comp))
        raw_variants.extend(_mutate_percent_encode(comp))
        
    # 4. Deduplicate and cap at 25 variants
    seen_urls = {norm_url.lower()}
    unique_variants: List[Tuple[str, str]] = []
    
    for v_url, op in raw_variants:
        v_clean = v_url.strip()
        v_lower = v_clean.lower()
        if v_lower not in seen_urls:
            seen_urls.add(v_lower)
            unique_variants.append((v_clean, op))
            if len(unique_variants) >= 25:
                break
                
    # 5. Score each variant with analyze_url()
    variant_results = []
    ml_dropped_count = 0
    still_flagged_count = 0
    still_flagged_after_ml_drop_count = 0
    
    for v_url, op in unique_variants:
        res = analyze_url(v_url)
        if "error" in res:
            continue
            
        v_score = res.get("risk_score", 0)
        v_class = res.get("classification", "legitimate")
        v_ml_prob = round(res.get("confidence", 0.0), 4)
        
        delta_score = v_score - orig_risk_score
        delta_ml = round(v_ml_prob - orig_ml_prob, 4)
        ml_dropped = delta_ml < -0.05
        still_flagged = v_class == "phishing"
        
        if ml_dropped:
            ml_dropped_count += 1
        if still_flagged:
            still_flagged_count += 1
        if ml_dropped and still_flagged:
            still_flagged_after_ml_drop_count += 1
            
        variant_results.append({
            "url": v_url,
            "operator": op,
            "risk_score": v_score,
            "ml_probability": v_ml_prob,
            "classification": v_class,
            "delta_score": delta_score,
            "delta_ml": delta_ml,
            "ml_dropped": ml_dropped,
            "still_flagged": still_flagged
        })
        
    # Check if model is loaded (from analyze_url output or model_loader)
    from app.models.loader import is_model_loaded
    model_loaded = is_model_loaded()
    
    summary = {
        "total": len(variant_results),
        "ml_dropped_count": ml_dropped_count,
        "still_flagged_count": still_flagged_count,
        "still_flagged_after_ml_drop_count": still_flagged_after_ml_drop_count
    }
    
    return {
        "original": original_summary,
        "model_loaded": model_loaded,
        "variants": variant_results,
        "summary": summary
    }
