import httpx
import re
import logging
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from config.settings import SCAN_TIMEOUT, USER_AGENT
from config.settings import BASE_DIR
import json

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login", "/login",
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/backup", "/backups", "/db", "/database", "/dump",
    "/config", "/configuration", "/.env", "/.git",
    "/phpinfo", "/info.php", "/test", "/debug",
    "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    "/phpmyadmin", "/pma", "/mysql",
    "/tmp", "/temp", "/cache", "/logs", "/log",
    "/.ssh", "/.aws", "/credentials", "/secrets",
    "/swagger", "/api-docs", "/redoc",
    "/console", "/actuator", "/health", "/metrics",
    "/docker-compose", "/Dockerfile", "/Makefile",
]


async def analyze_robots_and_sitemap(url: str) -> dict:
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.hostname}"

    headers = {"User-Agent": USER_AGENT}
    result = {
        "robots_found": False,
        "robots_paths": [],
        "sitemaps": [],
        "sitemap_urls": [],
        "sensitive_exposed": [],
        "risk_level": "LOW",
    }

    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=True) as client:
        try:
            resp = await client.get(f"{base_url}/robots.txt", headers=headers)
            if resp.status_code == 200:
                result["robots_found"] = True
                lines = resp.text.split("\n")
                disallowed = []
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed.append(path)
                    if line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        result["sitemaps"].append(sitemap_url)

                for path in disallowed:
                    risk = "HIGH" if any(path.lower().startswith(s) for s in ["/admin", "/.env", "/.git", "/backup", "/config", "/.ssh", "/.aws"]) else "MEDIUM"
                    result["robots_paths"].append({"path": path, "risk": risk})

                sig_file = BASE_DIR / "data" / "signatures.json"
                if sig_file.exists():
                    with open(sig_file) as f:
                        sigs = json.load(f)
                    sensitive_files = sigs.get("sensitive_files", [])
                    for path in disallowed:
                        for sf in sensitive_files:
                            if sf.lower() in path.lower():
                                result["sensitive_exposed"].append({"path": path, "source": "robots.txt", "risk": "HIGH"})

        except Exception as e:
            logger.debug(f"robots.txt error: {e}")

        for sm_url in result["sitemaps"][:3]:
            try:
                full_url = sm_url if sm_url.startswith("http") else f"{base_url}{sm_url}"
                resp = await client.get(full_url, headers=headers)
                if resp.status_code == 200:
                    result["sitemap_urls"].append({"url": full_url, "status": "accessible"})
                    soup = BeautifulSoup(resp.text, "xml")
                    locs = soup.find_all("loc")
                    for loc in locs[:50]:
                        loc_url = loc.text.strip()
                        loc_parsed = urlparse(loc_url)
                        loc_path = loc_parsed.path
                        for sp in SENSITIVE_PATHS:
                            if sp.lower() in loc_path.lower():
                                result["sensitive_exposed"].append({"path": loc_path, "source": "sitemap", "risk": "MEDIUM"})
            except Exception as e:
                result["sitemap_urls"].append({"url": sm_url, "status": f"error: {str(e)}"})

        for sp in SENSITIVE_PATHS:
            try:
                resp = await client.get(f"{base_url}{sp}", headers=headers)
                if resp.status_code == 200 and len(resp.text) > 100:
                    already = any(e["path"] == sp for e in result["sensitive_exposed"])
                    if not already:
                        result["sensitive_exposed"].append({"path": sp, "source": "direct_scan", "risk": "MEDIUM"})
            except Exception:
                pass

    if any(e["risk"] == "HIGH" for e in result["sensitive_exposed"]):
        result["risk_level"] = "HIGH"
    elif result["sensitive_exposed"]:
        result["risk_level"] = "MEDIUM"

    return result
