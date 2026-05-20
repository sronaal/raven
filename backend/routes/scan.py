from fastapi import APIRouter, HTTPException
from datetime import datetime, timezone
import json
import logging
from pathlib import Path

from utils.validators import validate_url, normalize_url
from services.http_fetcher import fetch_url
from services.header_analyzer import analyze_headers
from services.tech_detector import detect_technologies
from services.vulnerability_checker import check_vulnerabilities, calculate_vulnerability_score, fetch_external_cves
from services.ssl_analyzer import analyze_ssl
from services.parameter_analyzer import analyze_parameters
from config.settings import BASE_DIR

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/scan/level1")
async def scan_level1(request: dict):
    url = request.get("url", "")
    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)

    url = normalize_url(url)
    logger.info(f"Level 1 scan requested for: {url}")

    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        raise HTTPException(status_code=502, detail=fetch_result["error"])

    headers = fetch_result.get("headers", {})
    body = fetch_result.get("body", "")

    header_analysis = analyze_headers(headers)
    technologies = detect_technologies(headers, body)

    server_info = {"type": "Unknown", "version": None, "vulnerability": "unknown"}
    for tech in technologies:
        if tech.get("type") == "Web Server":
            server_info = {
                "type": tech["name"],
                "version": tech.get("version"),
                "vulnerability": "check_level2",
            }
            break

    return {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success",
        "server": server_info,
        "technologies": technologies,
        "headers": header_analysis,
        "security_score": header_analysis["score"],
    }

@router.post("/scan/level2")
async def scan_level2(request: dict):
    url = request.get("url", "")
    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)

    url = normalize_url(url)
    logger.info(f"Level 2 scan requested for: {url}")

    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        raise HTTPException(status_code=502, detail=fetch_result["error"])

    headers = fetch_result.get("headers", {})
    body = fetch_result.get("body", "")

    technologies = detect_technologies(headers, body)
    vulnerabilities = check_vulnerabilities(technologies)

    external_cves = []
    for tech in technologies[:3]:
        ext = await fetch_external_cves(tech["name"], tech.get("version", ""))
        external_cves.extend(ext)

    all_vulnerabilities = vulnerabilities + external_cves
    seen_ids = set()
    unique_vulnerabilities = []
    for v in all_vulnerabilities:
        if v["id"] not in seen_ids:
            seen_ids.add(v["id"])
            unique_vulnerabilities.append(v)

    ssl_analysis = await analyze_ssl(url)

    hsts_found = False
    for key in headers:
        if key.lower() == "strict-transport-security":
            hsts_found = True
            break

    waf_detected = detect_waf(headers)

    vuln_score = calculate_vulnerability_score(unique_vulnerabilities)

    return {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success",
        "vulnerabilities": unique_vulnerabilities,
        "ssl_tls": ssl_analysis,
        "hsts_enabled": hsts_found,
        "waf_detected": waf_detected,
        "vulnerability_score": vuln_score,
    }

@router.post("/scan/level3")
async def scan_level3(request: dict):
    url = request.get("url", "")
    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)

    url = normalize_url(url)
    logger.info(f"Level 3 scan requested for: {url}")

    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        raise HTTPException(status_code=502, detail=fetch_result["error"])

    headers = fetch_result.get("headers", {})
    body = fetch_result.get("body", "")

    parameter_analysis = analyze_parameters(url, headers, body)

    csrf_detected = detect_csrf_protection(headers, body)
    rate_limit_detected = detect_rate_limit(headers)

    return {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success",
        "parameters": parameter_analysis["parameters"],
        "xss_vectors": parameter_analysis["xss_vectors"],
        "other_risks": parameter_analysis["other_risks"],
        "path_parameters": parameter_analysis["path_parameters"],
        "csrf_protection": csrf_detected,
        "rate_limiting": rate_limit_detected,
        "parameter_score": parameter_analysis["score"],
    }

@router.post("/scan/full")
async def scan_full(request: dict):
    url = request.get("url", "")
    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)

    url = normalize_url(url)
    logger.info(f"Full scan requested for: {url}")

    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        raise HTTPException(status_code=502, detail=fetch_result["error"])

    headers = fetch_result.get("headers", {})
    body = fetch_result.get("body", "")

    header_analysis = analyze_headers(headers)
    technologies = detect_technologies(headers, body)
    vulnerabilities = check_vulnerabilities(technologies)
    ssl_analysis = await analyze_ssl(url)
    parameter_analysis = analyze_parameters(url, headers, body)

    server_info = {"type": "Unknown", "version": None, "vulnerability": "unknown"}
    for tech in technologies:
        if tech.get("type") == "Web Server":
            server_info = {
                "type": tech["name"],
                "version": tech.get("version"),
                "vulnerability": "check_level2",
            }
            break

    vuln_score = calculate_vulnerability_score(vulnerabilities)

    score1 = header_analysis["score"]
    score2 = vuln_score
    score3 = parameter_analysis["score"]
    total_score = int(score1 * 0.3 + score2 * 0.4 + score3 * 0.3)

    recommendations = generate_recommendations(header_analysis, vulnerabilities, parameter_analysis)

    return {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success",
        "nivel1": {
            "server": server_info,
            "technologies": technologies,
            "headers": header_analysis,
            "security_score": score1,
        },
        "nivel2": {
            "vulnerabilities": vulnerabilities,
            "ssl_tls": ssl_analysis,
            "vulnerability_score": score2,
        },
        "nivel3": {
            "parameters": parameter_analysis["parameters"],
            "xss_vectors": parameter_analysis["xss_vectors"],
            "other_risks": parameter_analysis["other_risks"],
            "parameter_score": score3,
        },
        "resumen_general": {
            "total_score": total_score,
            "score_breakdown": {
                "level1_fingerprinting": score1,
                "level2_vulnerabilities": score2,
                "level3_parameters": score3,
            },
            "priority_recommendations": recommendations,
            "resources": [
                "https://owasp.org/Top10/",
                "https://cwe.mitre.org/top25/",
                "https://observatory.mozilla.org/",
            ],
        },
    }

def detect_waf(headers: dict) -> dict:
    sig_file = BASE_DIR / "data" / "signatures.json"
    if not sig_file.exists():
        return {"detected": False}

    with open(sig_file) as f:
        signatures = json.load(f)

    for waf in signatures.get("waf_signatures", []):
        for header_name in waf.get("headers", []):
            for key in headers:
                if key.lower() == header_name.lower():
                    return {"detected": True, "name": waf["name"], "confidence": "high"}
        for cookie_name in waf.get("cookies", []):
            for key in headers:
                if key.lower() == "set-cookie" and cookie_name.lower() in headers[key].lower():
                    return {"detected": True, "name": waf["name"], "confidence": "medium"}

    return {"detected": False}

def detect_csrf_protection(headers: dict, body: str) -> dict:
    csrf_patterns = ["csrf_token", "_csrf", "csrfmiddlewaretoken", "authenticity_token"]
    found_tokens = []

    for pattern in csrf_patterns:
        if pattern.lower() in body.lower():
            found_tokens.append(pattern)

    same_site = False
    for key in headers:
        if key.lower() == "set-cookie" and "samesite" in headers[key].lower():
            same_site = True
            break

    return {
        "present": len(found_tokens) > 0 or same_site,
        "tokens_found": found_tokens,
        "samesite_cookie": same_site,
    }

def detect_rate_limit(headers: dict) -> dict:
    rate_limit_headers = [
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "retry-after",
        "rate-limit",
        "x-rate-limit",
    ]

    found = []
    for key in headers:
        if key.lower() in rate_limit_headers:
            found.append({"name": key, "value": headers[key]})

    return {
        "detected": len(found) > 0,
        "headers": found,
    }

def generate_recommendations(header_analysis: dict, vulnerabilities: list, parameter_analysis: dict) -> list:
    recommendations = []

    for missing in header_analysis.get("missing_critical", []):
        recommendations.append(f"Add {missing['name']} header: {missing['recommendation']}")

    for vuln in vulnerabilities:
        if vuln.get("severity") in ["CRITICAL", "HIGH"]:
            recommendations.append(f"Fix {vuln['id']}: {vuln.get('solution', 'Update component')}")

    for param in parameter_analysis.get("parameters", []):
        if param.get("risk") == "HIGH":
            recommendations.append(f"Secure parameter '{param['name']}': {param.get('mitigation', 'Add input validation')}")

    if not recommendations:
        recommendations.append("No critical issues found. Continue monitoring for new vulnerabilities.")

    return recommendations[:10]
