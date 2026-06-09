import logging
import re
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

RESOURCE_PATTERNS = [
    (r'<img[^>]+src=["\'](http://[^"\']+)["\']', "img"),
    (r'<script[^>]+src=["\'](http://[^"\']+)["\']', "script"),
    (r'<link[^>]+href=["\'](http://[^"\']+)["\']', "link"),
    (r'<iframe[^>]+src=["\'](http://[^"\']+)["\']', "iframe"),
    (r'<source[^>]+src=["\'](http://[^"\']+)["\']', "source"),
    (r'<video[^>]+src=["\'](http://[^"\']+)["\']', "video"),
    (r'<audio[^>]+src=["\'](http://[^"\']+)["\']', "audio"),
    (r'<embed[^>]+src=["\'](http://[^"\']+)["\']', "embed"),
    (r'<object[^>]+data=["\'](http://[^"\']+)["\']', "object"),
    (r'url\(["\']?(http://[^"\'\)]+)["\']?\)', "css_url"),
    (r'fetch\(["\'](http://[^"\']+)["\']', "fetch"),
    (r'XMLHttpRequest\([^)]*\)[^;]*\.open\([^,]*,\s*["\'](http://[^"\']+)["\']', "xhr"),
]


def check_mixed_content(base_url: str, body: str) -> dict:
    if not body:
        return {"mixed_content": [], "total": 0, "has_mixed_content": False, "risk": "none"}

    parsed_base = urlparse(base_url)
    if parsed_base.scheme != "https":
        return {"mixed_content": [], "total": 0, "has_mixed_content": False, "risk": "none", "note": "Site is not HTTPS — mixed content not applicable"}

    base_hostname = parsed_base.hostname or ""
    findings = []

    for pattern, tag in RESOURCE_PATTERNS:
        for match in re.finditer(pattern, body, re.IGNORECASE):
            resource_url = match.group(1)
            findings.append({
                "resource_url": resource_url,
                "type": tag,
                "hostname": urlparse(resource_url).hostname or "unknown",
                "same_origin": (urlparse(resource_url).hostname or "").lower() == base_hostname.lower(),
            })

    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["resource_url"], f["type"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    same_origin = [f for f in unique_findings if f["same_origin"]]
    cross_origin = [f for f in unique_findings if not f["same_origin"]]

    risk = "none"
    if len(unique_findings) > 0:
        if len(same_origin) > 0:
            risk = "high"
        else:
            risk = "medium"

    return {
        "mixed_content": unique_findings,
        "total": len(unique_findings),
        "same_origin": len(same_origin),
        "cross_origin": len(cross_origin),
        "has_mixed_content": len(unique_findings) > 0,
        "risk": risk,
        "types": list(set(f["type"] for f in unique_findings)),
    }
