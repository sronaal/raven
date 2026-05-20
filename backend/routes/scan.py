from fastapi import APIRouter, HTTPException, Request, Query
from datetime import datetime, timezone
import json
import asyncio
import logging
from pathlib import Path
from slowapi import Limiter
from slowapi.util import get_remote_address

from utils.validators import validate_url, normalize_url, validate_resolved_ip
from services.http_fetcher import fetch_url
from services.header_analyzer import analyze_headers
from services.tech_detector import detect_technologies
from services.vulnerability_checker import check_vulnerabilities, calculate_vulnerability_score, fetch_external_cves
from services.ssl_analyzer import analyze_ssl
from services.parameter_analyzer import analyze_parameters
from services.scan_store import save_scan
from services.ws_manager import manager
from services.redirect_analyzer import analyze_redirect_chain
from services.subdomain_enum import enumerate_subdomains
from services.robots_analyzer import analyze_robots_and_sitemap
from services.cookie_analyzer import analyze_cookie
from services.mozilla_grading import calculate_mozilla_grade
from config.settings import BASE_DIR, RATE_LIMIT
from routes.models import ScanRequest

router = APIRouter()
logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)


async def emit_progress(client_ip: str, event: str, progress: int, message: str, data: dict = None):
    payload = {"type": "progress", "event": event, "progress": progress, "message": message}
    if data:
        payload["data"] = data
    await manager.send_personal(payload, client_ip)


async def validate_and_fetch(url: str, level_name: str, client_ip: str = "") -> tuple[str, dict]:
    is_valid, message = validate_url(url)
    if not is_valid:
        logger.warning({"event": "invalid_url", "url": url, "reason": message, "client_ip": client_ip})
        raise HTTPException(status_code=400, detail=message)

    await emit_progress(client_ip, "validating", 10, "Validating URL...")
    url = normalize_url(url)
    logger.info({"event": "scan_started", "level": level_name, "url": url, "client_ip": client_ip})

    await emit_progress(client_ip, "fetching", 20, "Fetching target...")
    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        logger.error({"event": "fetch_error", "url": url, "error": fetch_result["error"], "client_ip": client_ip})
        raise HTTPException(status_code=502, detail=fetch_result["error"])

    resolved_url = fetch_result.get("url", url)
    ip_valid, ip_msg = validate_resolved_ip(url, resolved_url)
    if not ip_valid:
        logger.warning({"event": "dns_rebinding_blocked", "url": url, "resolved_url": resolved_url, "reason": ip_msg, "client_ip": client_ip})
        raise HTTPException(status_code=403, detail=ip_msg)

    logger.info({"event": "scan_completed", "level": level_name, "url": url, "client_ip": client_ip})
    return url, fetch_result


def extract_server_info(technologies: list) -> dict:
    for tech in technologies:
        if tech.get("type") == "Web Server":
            return {
                "type": tech["name"],
                "version": tech.get("version"),
                "vulnerability": "check_level2",
            }
    return {"type": "Unknown", "version": None, "vulnerability": "unknown"}


def deduplicate_vulnerabilities(vulns: list) -> list:
    seen_ids = set()
    unique = []
    for v in vulns:
        if v["id"] not in seen_ids:
            seen_ids.add(v["id"])
            unique.append(v)
    return unique

@router.post("/scan/level1")
@limiter.limit(RATE_LIMIT)
async def scan_level1(request: Request):
    body = await request.json()
    scan_req = ScanRequest(**body)
    url = scan_req.url
    url, fetch_result = await validate_and_fetch(url, "Level 1", request.client.host if request.client else "")

    headers = fetch_result.get("headers", {})
    body_content = fetch_result.get("body", "")

    header_analysis = analyze_headers(headers)
    technologies = detect_technologies(headers, body_content)
    server_info = extract_server_info(technologies)

    result = {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success",
        "server": server_info,
        "technologies": technologies,
        "headers": header_analysis,
        "security_score": header_analysis["score"],
    }
    client_ip_str = request.client.host if request.client else ""
    result["scan_id"] = save_scan(url, result["timestamp"], "level1", {"nivel1": result, "resumen_general": {"total_score": header_analysis["score"]}}, client_ip_str)
    return result

@router.post("/scan/level2")
@limiter.limit(RATE_LIMIT)
async def scan_level2(request: Request):
    body = await request.json()
    scan_req = ScanRequest(**body)
    url = scan_req.url
    url, fetch_result = await validate_and_fetch(url, "Level 2", request.client.host if request.client else "")

    headers = fetch_result.get("headers", {})
    body_content = fetch_result.get("body", "")

    technologies = detect_technologies(headers, body_content)
    vulnerabilities = check_vulnerabilities(technologies)

    external_cves = []
    for tech in technologies[:3]:
        ext = await fetch_external_cves(tech["name"], tech.get("version", ""))
        external_cves.extend(ext)

    unique_vulnerabilities = deduplicate_vulnerabilities(vulnerabilities + external_cves)
    ssl_analysis = await analyze_ssl(url)

    hsts_found = any(k.lower() == "strict-transport-security" for k in headers)
    waf_detected = detect_waf(headers)
    vuln_score = calculate_vulnerability_score(unique_vulnerabilities)

    result = {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success",
        "vulnerabilities": unique_vulnerabilities,
        "ssl_tls": ssl_analysis,
        "hsts_enabled": hsts_found,
        "waf_detected": waf_detected,
        "vulnerability_score": vuln_score,
    }
    client_ip_str = request.client.host if request.client else ""
    result["scan_id"] = save_scan(url, result["timestamp"], "level2", {"nivel2": result, "resumen_general": {"total_score": vuln_score}}, client_ip_str)
    return result

@router.post("/scan/level3")
@limiter.limit(RATE_LIMIT)
async def scan_level3(request: Request):
    body = await request.json()
    scan_req = ScanRequest(**body)
    url = scan_req.url
    url, fetch_result = await validate_and_fetch(url, "Level 3", request.client.host if request.client else "")

    headers = fetch_result.get("headers", {})
    body_content = fetch_result.get("body", "")

    parameter_analysis = analyze_parameters(url, headers, body_content)
    csrf_detected = detect_csrf_protection(headers, body_content)
    rate_limit_detected = detect_rate_limit(headers)

    result = {
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
    client_ip_str = request.client.host if request.client else ""
    result["scan_id"] = save_scan(url, result["timestamp"], "level3", {"nivel3": result, "resumen_general": {"total_score": parameter_analysis["score"]}}, client_ip_str)
    return result

@router.post("/scan/full")
@limiter.limit(RATE_LIMIT)
async def scan_full(request: Request):
    body = await request.json()
    scan_req = ScanRequest(**body)
    url = scan_req.url
    url, fetch_result = await validate_and_fetch(url, "Full", request.client.host if request.client else "")

    headers = fetch_result.get("headers", {})
    body_content = fetch_result.get("body", "")

    client_ip_str = request.client.host if request.client else ""
    await emit_progress(client_ip_str, "analyzing_headers", 30, "Analyzing headers...")

    header_analysis = analyze_headers(headers)
    technologies = detect_technologies(headers, body_content)

    await emit_progress(client_ip_str, "checking_cves", 50, "Checking vulnerabilities...")
    vulnerabilities = check_vulnerabilities(technologies)

    await emit_progress(client_ip_str, "analyzing_ssl", 70, "Analyzing SSL/TLS...")
    ssl_analysis = await analyze_ssl(url)

    await emit_progress(client_ip_str, "analyzing_params", 85, "Analyzing parameters...")
    parameter_analysis = analyze_parameters(url, headers, body_content)

    server_info = extract_server_info(technologies)
    vuln_score = calculate_vulnerability_score(vulnerabilities)

    score1 = header_analysis["score"]
    score2 = vuln_score
    score3 = parameter_analysis["score"]
    total_score = int(score1 * 0.3 + score2 * 0.4 + score3 * 0.3)

    recommendations = generate_recommendations(header_analysis, vulnerabilities, parameter_analysis)

    result = {
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

    client_ip_str = request.client.host if request.client else ""
    scan_id = save_scan(url, result["timestamp"], "full", result, client_ip_str)
    result["scan_id"] = scan_id

    await emit_progress(client_ip_str, "complete", 100, "Scan complete", {"scan_id": scan_id})

    return result


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


@router.post("/scan/redirects")
@limiter.limit(RATE_LIMIT)
async def scan_redirects(request: Request):
    body = await request.json()
    scan_req = ScanRequest(**body)
    url = scan_req.url
    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)

    url = normalize_url(url)
    client_ip_str = request.client.host if request.client else ""
    logger.info({"event": "redirect_analysis", "url": url, "client_ip": client_ip_str})

    result = await analyze_redirect_chain(url)
    return {"url": url, "timestamp": datetime.now(timezone.utc).isoformat(), **result}


@router.post("/scan/subdomains")
@limiter.limit(RATE_LIMIT)
async def scan_subdomains(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    parsed = urlparse(url)
    hostname = parsed.hostname or url
    if hostname.startswith("www."):
        hostname = hostname[4:]

    client_ip_str = request.client.host if request.client else ""
    logger.info({"event": "subdomain_enum", "domain": hostname, "client_ip": client_ip_str})

    result = await enumerate_subdomains(hostname)
    return {"domain": hostname, "timestamp": datetime.now(timezone.utc).isoformat(), **result}


@router.post("/scan/robots")
@limiter.limit(RATE_LIMIT)
async def scan_robots(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    url = normalize_url(url)
    client_ip_str = request.client.host if request.client else ""
    logger.info({"event": "robots_analysis", "url": url, "client_ip": client_ip_str})

    result = await analyze_robots_and_sitemap(url)
    return {"url": url, "timestamp": datetime.now(timezone.utc).isoformat(), **result}


@router.post("/scan/batch")
async def scan_batch(request: Request):
    body = await request.json()
    urls = body.get("urls", [])
    if not isinstance(urls, list) or not urls:
        raise HTTPException(status_code=400, detail="urls array is required")
    if len(urls) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 URLs per batch")

    client_ip_str = request.client.host if request.client else ""
    level = body.get("level", "full")

    async def scan_one(url: str):
        try:
            is_valid, message = validate_url(url)
            if not is_valid:
                return {"url": url, "status": "error", "error": message}

            url = normalize_url(url)
            fetch_result = await fetch_url(url)
            if "error" in fetch_result:
                return {"url": url, "status": "error", "error": fetch_result["error"]}

            headers = fetch_result.get("headers", {})
            body_content = fetch_result.get("body", "")

            header_analysis = analyze_headers(headers)
            technologies = detect_technologies(headers, body_content)

            if level == "level1":
                score = header_analysis["score"]
            elif level == "level2":
                vulns = check_vulnerabilities(technologies)
                score = calculate_vulnerability_score(vulns)
            elif level == "level3":
                param_analysis = analyze_parameters(url, headers, body_content)
                score = param_analysis["score"]
            else:
                vulns = check_vulnerabilities(technologies)
                param_analysis = analyze_parameters(url, headers, body_content)
                s1 = header_analysis["score"]
                s2 = calculate_vulnerability_score(vulns)
                s3 = param_analysis["score"]
                score = int(s1 * 0.3 + s2 * 0.4 + s3 * 0.3)

            return {"url": url, "status": "success", "score": score, "technologies": len(technologies)}
        except Exception as e:
            return {"url": url, "status": "error", "error": str(e)}

    results = await asyncio.gather(*[scan_one(u) for u in urls])
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": len(urls),
        "successful": sum(1 for r in results if r["status"] == "success"),
        "failed": sum(1 for r in results if r["status"] == "error"),
        "results": results,
    }


@router.post("/scan/cookies")
@limiter.limit(RATE_LIMIT)
async def scan_cookies(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    url = normalize_url(url)
    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        raise HTTPException(status_code=502, detail=fetch_result["error"])

    headers = fetch_result.get("headers", {})
    cookies = []
    set_cookie = headers.get("Set-Cookie", headers.get("set-cookie", ""))
    if set_cookie:
        for cookie_str in set_cookie.split(", "):
            if "=" in cookie_str:
                cookies.append(analyze_cookie(cookie_str.strip()))

    return {"url": url, "timestamp": datetime.now(timezone.utc).isoformat(), "cookies": cookies, "total": len(cookies)}


@router.post("/scan/grade")
@limiter.limit(RATE_LIMIT)
async def scan_grade(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    url = normalize_url(url)
    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        raise HTTPException(status_code=502, detail=fetch_result["error"])

    headers = fetch_result.get("headers", {})
    body_content = fetch_result.get("body", "")

    header_analysis = analyze_headers(headers)
    technologies = detect_technologies(headers, body_content)
    vulnerabilities = check_vulnerabilities(technologies)
    ssl_analysis = await analyze_ssl(url)
    vuln_score = calculate_vulnerability_score(vulnerabilities)

    grade = calculate_mozilla_grade(header_analysis, ssl_analysis, vuln_score)

    return {"url": url, "timestamp": datetime.now(timezone.utc).isoformat(), **grade}
