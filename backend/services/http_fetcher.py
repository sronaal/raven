import httpx
import logging
from config.settings import SCAN_TIMEOUT, USER_AGENT, MAX_BODY_SIZE

logger = logging.getLogger(__name__)

async def fetch_url(url: str) -> dict:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    async with httpx.AsyncClient(
        timeout=SCAN_TIMEOUT,
        follow_redirects=True,
        verify=True,
    ) as client:
        try:
            response = await client.get(url, headers=headers)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:MAX_BODY_SIZE],
                "url": str(response.url),
                "elapsed": response.elapsed.total_seconds(),
            }
        except httpx.ConnectTimeout:
            return {"error": "Connection timeout"}
        except httpx.ConnectError as e:
            return {"error": f"Connection error: {str(e)}"}
        except httpx.TooManyRedirects:
            return {"error": "Too many redirects"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

async def fetch_url_head(url: str) -> dict:
    headers = {"User-Agent": USER_AGENT}
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        try:
            response = await client.head(url, headers=headers)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
            }
        except Exception:
            return await fetch_url(url)
