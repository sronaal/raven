import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

HIGH_RISK_PARAMS = ["id", "user_id", "token", "session", "password", "api_key", "secret", "key", "auth"]
SENSITIVE_TECHS = ["Apache", "Nginx", "IIS", "PHP", "WordPress", "Drupal", "Joomla", "Magento"]


def map_attack_surface(url: str, subdomains: list, crawler_result: dict, api_result: dict, technologies: list, vulnerabilities: list, header_analysis: dict, ssl_analysis: dict) -> dict:
    nodes = []
    edges = []
    risk_scores = {}

    root_node = {"id": "root", "label": urlparse(url).hostname, "type": "domain", "risk": "LOW", "children": 0}
    nodes.append(root_node)

    for sub in (subdomains or []):
        risk = "MEDIUM"
        if any(w in sub for w in ["dev", "staging", "test", "admin", "api"]):
            risk = "HIGH"
        node = {"id": f"sub_{sub}", "label": sub, "type": "subdomain", "risk": risk}
        nodes.append(node)
        edges.append({"from": "root", "to": f"sub_{sub}"})

    endpoints = (crawler_result or {}).get("endpoints", [])
    for ep in endpoints:
        ep_risk = "LOW"
        if ep.get("status_code") == 200 and any(p in ep["url"].lower() for p in ["/admin", "/api", "/config", "/debug"]):
            ep_risk = "HIGH"
        elif ep.get("status_code", 0) >= 500:
            ep_risk = "MEDIUM"
        elif ep.get("type") == "api":
            ep_risk = "MEDIUM"

        params_count = ep.get("url", "").count("=") + ep.get("url", "").count("?")
        if any(p in ep["url"].lower() for p in HIGH_RISK_PARAMS):
            ep_risk = "HIGH"

        node_id = f"ep_{ep['url']}"
        nodes.append({"id": node_id, "label": ep["url"].split("/")[-1][:30], "type": ep.get("type", "endpoint"), "risk": ep_risk, "full_url": ep["url"], "status": ep.get("status_code")})
        edges.append({"from": "root", "to": node_id})
        risk_scores[ep["url"]] = ep_risk

    api_paths = (api_result or {}).get("api_paths_from_specs", [])
    for api in api_paths:
        node_id = f"api_{api['path']}"
        nodes.append({"id": node_id, "label": f"{api['method']} {api['path']}", "type": "api_spec", "risk": "MEDIUM", "method": api["method"], "path": api["path"]})
        edges.append({"from": "root", "to": node_id})

    for tech in (technologies or []):
        if tech.get("name") in SENSITIVE_TECHS:
            tech_risk = "HIGH" if any(v.get("severity") in ("CRITICAL", "HIGH") for v in vulnerabilities) else "MEDIUM"
            nodes.append({"id": f"tech_{tech['name']}", "label": f"{tech['name']} {tech.get('version', '')}", "type": "technology", "risk": tech_risk})
            edges.append({"from": "root", "to": f"tech_{tech['name']}"})

    for v in (vulnerabilities or [])[:10]:
        nodes.append({"id": f"vuln_{v['id']}", "label": v["id"], "type": "vulnerability", "risk": v.get("severity", "MEDIUM"), "severity": v.get("severity")})
        edges.append({"from": "root", "to": f"vuln_{v['id']}"})

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for n in nodes:
        r = n.get("risk", "LOW")
        if r in risk_counts:
            risk_counts[r] += 1

    overall_risk = "CRITICAL" if risk_counts["CRITICAL"] > 0 else "HIGH" if risk_counts["HIGH"] > 2 else "MEDIUM" if risk_counts["MEDIUM"] > 5 else "LOW"

    return {
        "nodes": nodes[:100],
        "edges": edges[:100],
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "risk_counts": risk_counts,
        "overall_risk": overall_risk,
        "surface_score": _calculate_surface_score(risk_counts, len(nodes), len(vulnerabilities)),
    }


def _calculate_surface_score(risk_counts: dict, total_nodes: int, vuln_count: int) -> int:
    score = 100
    score -= risk_counts["CRITICAL"] * 20
    score -= risk_counts["HIGH"] * 10
    score -= risk_counts["MEDIUM"] * 5
    score -= min(vuln_count * 3, 30)
    if total_nodes > 50:
        score -= 10
    return max(0, min(100, score))
