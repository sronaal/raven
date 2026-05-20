from fastapi import APIRouter, HTTPException, Request
from datetime import datetime, timezone
import logging

from services.crawler import crawl_site
from services.owasp_checker import check_owasp_top10
from services.api_discovery import discover_apis
from services.dependency_checker import check_dependencies
from services.attack_surface import map_attack_surface
from services.compliance_checker import check_compliance
from services.http_fetcher import fetch_url
from services.header_analyzer import analyze_headers
from services.tech_detector import detect_technologies
from services.vulnerability_checker import check_vulnerabilities
from services.ssl_analyzer import analyze_ssl
from services.parameter_analyzer import analyze_parameters
from utils.validators import validate_url, normalize_url

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/crawl")
async def crawl(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)

    url = normalize_url(url)
    max_depth = body.get("max_depth", 3)
    max_pages = body.get("max_pages", 50)

    if max_depth > 5:
        raise HTTPException(status_code=400, detail="max_depth cannot exceed 5")
    if max_pages > 200:
        raise HTTPException(status_code=400, detail="max_pages cannot exceed 200")

    logger.info({"event": "crawl_started", "url": url, "max_depth": max_depth, "max_pages": max_pages})

    result = await crawl_site(url, max_depth=max_depth, max_pages=max_pages)
    return {"timestamp": datetime.now(timezone.utc).isoformat(), **result}


@router.post("/scan/owasp")
async def scan_owasp(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)

    url = normalize_url(url)
    logger.info({"event": "owasp_scan", "url": url})

    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        raise HTTPException(status_code=502, detail=fetch_result["error"])

    headers = fetch_result.get("headers", {})
    body_content = fetch_result.get("body", "")

    header_analysis = analyze_headers(headers)
    technologies = detect_technologies(headers, body_content)
    vulnerabilities = check_vulnerabilities(technologies)
    ssl_analysis = await analyze_ssl(url)
    parameter_analysis = analyze_parameters(url, headers, body_content)

    result = check_owasp_top10(headers, body_content, url, technologies, vulnerabilities, ssl_analysis, parameter_analysis)
    return {"url": url, "timestamp": datetime.now(timezone.utc).isoformat(), **result}


@router.post("/discover")
async def discover(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)
    url = normalize_url(url)
    result = await discover_apis(url)
    return {"url": url, "timestamp": datetime.now(timezone.utc).isoformat(), **result}


@router.post("/dependencies")
async def dependencies(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)
    url = normalize_url(url)
    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        raise HTTPException(status_code=502, detail=fetch_result["error"])
    body_content = fetch_result.get("body", "")
    result = check_dependencies(body_content, url)
    return {"url": url, "timestamp": datetime.now(timezone.utc).isoformat(), **result}


@router.post("/compliance")
async def compliance(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)
    url = normalize_url(url)
    fetch_result = await fetch_url(url)
    if "error" in fetch_result:
        raise HTTPException(status_code=502, detail=fetch_result["error"])
    headers = fetch_result.get("headers", {})
    body_content = fetch_result.get("body", "")
    ssl_analysis = await analyze_ssl(url)
    result = check_compliance(headers, body_content, ssl_analysis, url)
    return {"url": url, "timestamp": datetime.now(timezone.utc).isoformat(), **result}


@router.post("/surface")
async def surface(request: Request):
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    is_valid, message = validate_url(url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=message)
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
    parameter_analysis = analyze_parameters(url, headers, body_content)
    result = map_attack_surface(url, [], {}, {}, technologies, vulnerabilities, header_analysis, ssl_analysis)
    return {"url": url, "timestamp": datetime.now(timezone.utc).isoformat(), **result}
