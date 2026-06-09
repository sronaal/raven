import asyncio
import logging
import re
import time
from urllib.parse import urlparse, urljoin, urldefrag
from collections import deque
from bs4 import BeautifulSoup
import httpx

from config.settings import USER_AGENT, SCAN_TIMEOUT

logger = logging.getLogger(__name__)

JS_PATTERNS = [
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'XMLHttpRequest.*\.open\s*\(\s*["\']\w+["\']\s*,\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'\.get\s*\(\s*["\'](/[^"\']*)["\']', re.IGNORECASE),
    re.compile(r'\.post\s*\(\s*["\'](/[^"\']*)["\']', re.IGNORECASE),
    re.compile(r'window\.location\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'href\s*:\s*["\'](/[^"\']*)["\']', re.IGNORECASE),
    re.compile(r'url\s*:\s*["\'](/[^"\']*)["\']', re.IGNORECASE),
]

API_PATTERNS = [
    re.compile(r'/api/'),
    re.compile(r'/graphql'),
    re.compile(r'/rest/'),
    re.compile(r'/v\d+/'),
    re.compile(r'/wp-json/'),
    re.compile(r'/\.well-known/'),
]

IGNORE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip', '.tar', '.gz'}


async def crawl_site(url: str, max_depth: int = 3, max_pages: int = 50, delay: float = 0.5) -> dict:
    parsed = urlparse(url)
    base_domain = parsed.hostname
    base_url = f"{parsed.scheme}://{base_domain}"

    visited = set()
    queue = deque()
    queue.append((url, 0, "GET"))
    endpoints = []
    forms = []
    js_urls = []
    api_endpoints = []
    json_lds = []
    data_attributes = []
    errors = []
    pages_crawled = 0

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    async with httpx.AsyncClient(timeout=SCAN_TIMEOUT, follow_redirects=True, verify=True) as client:
        while queue and pages_crawled < max_pages:
            current_url, depth, method = queue.popleft()
            defragged = urldefrag(current_url)[0]

            if defragged in visited or depth > max_depth:
                continue
            visited.add(defragged)

            parsed_url = urlparse(defragged)
            if parsed_url.hostname != base_domain:
                continue

            ext = parsed_url.path.rsplit(".", 1)[-1] if "." in parsed_url.path else ""
            if f".{ext}" in IGNORE_EXTENSIONS:
                continue

            try:
                await asyncio.sleep(delay)
                resp = await client.get(defragged, headers=headers)
                pages_crawled += 1

                endpoint = {
                    "url": defragged,
                    "method": method,
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                    "content_length": len(resp.content),
                    "depth": depth,
                    "response_time_ms": round(resp.elapsed.total_seconds() * 1000, 1),
                    "type": _classify_endpoint(defragged, resp),
                }
                endpoints.append(endpoint)

                if any(p.search(defragged) for p in API_PATTERNS):
                    api_endpoints.append(endpoint)

                if resp.status_code in (200, 301, 302):
                    soup = BeautifulSoup(resp.text, "html.parser")

                    for script_ld in soup.find_all("script", type="application/ld+json"):
                        if script_ld.string:
                            json_lds.append({
                                "content": script_ld.string.strip()[:500],
                                "found_on": defragged,
                            })

                    for tag in soup.find_all(attrs={"data-": True}):
                        for attr in list(tag.attrs):
                            if attr.startswith("data-"):
                                data_attributes.append({
                                    "tag": tag.name,
                                    "attribute": attr,
                                    "value": tag[attr][:200],
                                    "found_on": defragged,
                                })

                    for a in soup.find_all("a", href=True):
                        href = a["href"].strip()
                        if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                            full_url = urljoin(defragged, href)
                            queue.append((urldefrag(full_url)[0], depth + 1, "GET"))

                    for form in soup.find_all("form"):
                        form_action = form.get("action", "")
                        form_method = form.get("method", "GET").upper()
                        full_action = urljoin(defragged, form_action) if form_action else defragged
                        inputs = []
                        for inp in form.find_all(["input", "select", "textarea"]):
                            inputs.append({
                                "name": inp.get("name", ""),
                                "type": inp.get("type", "text"),
                            })
                        forms.append({
                            "url": urldefrag(full_action)[0],
                            "method": form_method,
                            "inputs": inputs,
                            "found_on": defragged,
                        })
                        queue.append((urldefrag(full_action)[0], depth + 1, form_method))

                    for script in soup.find_all("script", src=True):
                        src = script["src"]
                        full_src = urljoin(defragged, src)
                        if full_src not in js_urls:
                            js_urls.append(full_src)

                    for link in soup.find_all("link", href=True):
                        href = link["href"]
                        if href.endswith(".js"):
                            full_js = urljoin(defragged, href)
                            if full_js not in js_urls:
                                js_urls.append(full_js)

                    for script in soup.find_all("script"):
                        if script.string:
                            for pattern in JS_PATTERNS:
                                for match in pattern.finditer(script.string):
                                    js_url = match.group(1)
                                    if js_url.startswith("/"):
                                        full = f"{base_url}{js_url}"
                                        if full not in [e["url"] for e in api_endpoints]:
                                            api_endpoints.append({
                                                "url": full,
                                                "method": "GET",
                                                "status_code": "discovered",
                                                "source": "javascript",
                                                "found_on": defragged,
                                            })

            except httpx.ConnectTimeout:
                errors.append({"url": defragged, "error": "timeout"})
            except Exception as e:
                errors.append({"url": defragged, "error": str(e)})

    return {
        "base_url": base_url,
        "pages_crawled": pages_crawled,
        "total_endpoints": len(endpoints),
        "api_endpoints": len(api_endpoints),
        "forms_found": len(forms),
        "js_files": len(js_urls),
        "json_ld_found": len(json_lds),
        "data_attributes_found": len(data_attributes),
        "endpoints": endpoints,
        "api_endpoints": api_endpoints,
        "forms": forms,
        "js_files": js_urls[:100],
        "json_ld": json_lds[:20],
        "data_attributes": data_attributes[:50],
        "errors": errors[:20],
        "summary": {
            "200": sum(1 for e in endpoints if e["status_code"] == 200),
            "3xx": sum(1 for e in endpoints if 300 <= e["status_code"] < 400),
            "4xx": sum(1 for e in endpoints if 400 <= e["status_code"] < 500),
            "5xx": sum(1 for e in endpoints if 500 <= e["status_code"] < 600),
        },
    }


def _classify_endpoint(url: str, resp) -> str:
    content_type = resp.headers.get("content-type", "")
    if "json" in content_type:
        return "api"
    if "html" in content_type:
        return "page"
    if "xml" in content_type:
        return "xml"
    if "javascript" in content_type:
        return "script"
    if any(p.search(url) for p in API_PATTERNS):
        return "api"
    return "other"
