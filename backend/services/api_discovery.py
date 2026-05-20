import httpx
import json
import logging
from urllib.parse import urlparse, urljoin
from config.settings import USER_AGENT, SCAN_TIMEOUT

logger = logging.getLogger(__name__)

SWAGGER_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/v3/api-docs", "/v2/api-docs",
    "/swagger/ui", "/docs", "/api/swagger.json", "/api/v1/openapi.json",
    "/api/swagger-ui.html", "/swagger-ui.html",
]

GRAPHQL_PATHS = ["/graphql", "/graphql/console", "/api/graphql", "/v1/graphql"]


async def discover_apis(url: str) -> dict:
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.hostname}"
    headers = {"User-Agent": USER_AGENT}
    result = {
        "openapi_specs": [],
        "graphql_endpoints": [],
        "api_paths_from_specs": [],
        "total_api_paths": 0,
    }

    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=True) as client:
        for path in SWAGGER_PATHS:
            try:
                resp = await client.get(f"{base_url}{path}", headers=headers)
                if resp.status_code == 200 and ("json" in resp.headers.get("content-type", "") or "html" in resp.headers.get("content-type", "")):
                    spec = None
                    if "json" in resp.headers.get("content-type", ""):
                        try:
                            spec = resp.json()
                        except Exception:
                            pass
                    result["openapi_specs"].append({
                        "url": f"{base_url}{path}",
                        "status": resp.status_code,
                        "has_spec": spec is not None,
                        "version": spec.get("openapi", spec.get("swagger", "unknown")) if spec else "unknown",
                    })
                    if spec:
                        paths = spec.get("paths", {})
                        for p, methods in paths.items():
                            for method in methods:
                                if method in ("get", "post", "put", "delete", "patch", "options", "head"):
                                    result["api_paths_from_specs"].append({
                                        "path": p,
                                        "method": method.upper(),
                                        "summary": methods[method].get("summary", ""),
                                        "tags": methods[method].get("tags", []),
                                    })
            except Exception as e:
                logger.debug(f"Swagger path {path} error: {e}")

        for path in GRAPHQL_PATHS:
            try:
                resp = await client.post(
                    f"{base_url}{path}",
                    headers={**headers, "Content-Type": "application/json"},
                    json={"query": "{ __schema { types { name } } }"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    result["graphql_endpoints"].append({
                        "url": f"{base_url}{path}",
                        "type_count": len(types),
                        "sample_types": [t["name"] for t in types[:10]],
                    })
            except Exception:
                pass

        result["total_api_paths"] = len(result["api_paths_from_specs"])

    return result
