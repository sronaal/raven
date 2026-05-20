import httpx
import logging
from urllib.parse import urlparse
from config.settings import CRT_SH_API, SCAN_TIMEOUT

logger = logging.getLogger(__name__)


async def enumerate_subdomains(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=SCAN_TIMEOUT) as client:
            response = await client.get(
                CRT_SH_API,
                params={"q": f"%.{domain}", "output": "json"},
                headers={"User-Agent": "URLSecurityScanner/1.0"},
            )
            if response.status_code != 200:
                return {"error": f"crt.sh returned status {response.status_code}", "subdomains": []}

            data = response.json()
            if isinstance(data, dict) and "error" in data:
                return {"error": data["error"], "subdomains": []}

            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n and n.endswith(f".{domain.lower()}"):
                        subdomains.add(n)

            sorted_subs = sorted(subdomains)
            wildcard = [s for s in sorted_subs if s.startswith("*.")]
            normal = [s for s in sorted_subs if not s.startswith("*.")]

            return {
                "domain": domain,
                "subdomains": normal,
                "wildcards": wildcard,
                "total": len(sorted_subs),
                "total_normal": len(normal),
                "total_wildcards": len(wildcard),
            }
    except httpx.ConnectTimeout:
        return {"error": "Connection timeout to crt.sh", "subdomains": []}
    except Exception as e:
        logger.error(f"Error enumerating subdomains: {e}")
        return {"error": str(e), "subdomains": []}
