import httpx
import logging
from urllib.parse import urlparse
from config.settings import SCAN_TIMEOUT, USER_AGENT

logger = logging.getLogger(__name__)

MAX_REDIRECTS = 10


async def analyze_redirect_chain(url: str) -> dict:
    headers = {"User-Agent": USER_AGENT}
    chain = []
    current_url = url
    visited = set()

    async with httpx.AsyncClient(
        timeout=SCAN_TIMEOUT,
        follow_redirects=False,
        verify=True,
    ) as client:
        for i in range(MAX_REDIRECTS):
            if current_url in visited:
                chain.append({
                    "step": i + 1,
                    "url": current_url,
                    "status_code": None,
                    "issue": "Redirect loop detected",
                    "risk": "HIGH",
                })
                break
            visited.add(current_url)

            try:
                response = await client.get(current_url, headers=headers)
            except Exception as e:
                chain.append({
                    "step": i + 1,
                    "url": current_url,
                    "status_code": None,
                    "issue": f"Request failed: {str(e)}",
                    "risk": "MEDIUM",
                })
                break

            step = {
                "step": i + 1,
                "url": current_url,
                "status_code": response.status_code,
                "server": response.headers.get("server", "Unknown"),
            }

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                step["redirect_to"] = location
                step["redirect_type"] = "permanent" if response.status_code in (301, 308) else "temporary"

                parsed_from = urlparse(current_url)
                parsed_to = urlparse(location)
                if parsed_from.hostname != parsed_to.hostname:
                    step["cross_domain"] = True
                    step["risk"] = "MEDIUM"
                    step["issue"] = "Cross-domain redirect"
                elif parsed_from.scheme == "http" and parsed_to.scheme == "https":
                    step["upgrade_to_https"] = True
                    step["risk"] = "LOW"
                    step["issue"] = "HTTP to HTTPS upgrade (good)"
                else:
                    step["risk"] = "LOW"

                chain.append(step)
                if location.startswith("http"):
                    current_url = location
                else:
                    current_url = f"{parsed_from.scheme}://{parsed_from.hostname}{location}"
            else:
                step["final"] = True
                step["risk"] = "INFO"
                chain.append(step)
                break

    issues = [s for s in chain if s.get("risk") in ("HIGH", "MEDIUM")]
    return {
        "chain": chain,
        "total_redirects": len(chain) - 1,
        "final_url": chain[-1]["url"] if chain else url,
        "has_loop": any("loop" in s.get("issue", "") for s in chain),
        "cross_domain_redirects": [s for s in chain if s.get("cross_domain")],
        "issues": issues,
        "risk_level": "HIGH" if any(s.get("risk") == "HIGH" for s in chain) else "MEDIUM" if issues else "LOW",
    }
