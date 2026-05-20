import re
import json
import logging
from pathlib import Path
from config.settings import BASE_DIR

logger = logging.getLogger(__name__)

CDN_PATTERNS = [
    (re.compile(r'cdn\.jsdelivr\.net/npm/([^@/]+)@([^/]+)', re.IGNORECASE), "jsdelivr"),
    (re.compile(r'unpkg\.com/([^@/]+)@([^/]+)', re.IGNORECASE), "unpkg"),
    (re.compile(r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)', re.IGNORECASE), "cdnjs"),
    (re.compile(r'code\.jquery\.com/jquery-([0-9.]+)', re.IGNORECASE), "jquery-cdn"),
    (re.compile(r'ajax\.googleapis\.com/ajax/libs/([^/]+)/([^/]+)', re.IGNORECASE), "google-cdn"),
    (re.compile(r'maxcdn\.bootstrapcdn\.com/bootstrap/([^/]+)', re.IGNORECASE), "bootstrap-cdn"),
]

LIB_PATTERNS = [
    (re.compile(r'jQuery\s*v?([0-9.]+)', re.IGNORECASE), "jQuery"),
    (re.compile(r'React\s*v?([0-9.]+)', re.IGNORECASE), "React"),
    (re.compile(r'Angular\s*v?([0-9.]+)', re.IGNORECASE), "Angular"),
    (re.compile(r'Vue\.?js\s*v?([0-9.]+)', re.IGNORECASE), "Vue.js"),
    (re.compile(r'Bootstrap\s*v?([0-9.]+)', re.IGNORECASE), "Bootstrap"),
    (re.compile(r'lodash\s*v?([0-9.]+)', re.IGNORECASE), "Lodash"),
    (re.compile(r'Moment\.?js\s*v?([0-9.]+)', re.IGNORECASE), "Moment.js"),
]

SENSITIVE_CONFIG_FILES = [
    "/package.json", "/composer.json", "/Gemfile.lock", "/pom.xml",
    "/requirements.txt", "/go.mod", "/Cargo.toml", "/yarn.lock",
    "/package-lock.json", "/pnpm-lock.yaml",
]


def check_dependencies(body: str, base_url: str) -> dict:
    dependencies = []
    seen = set()

    for pattern, cdn_name in CDN_PATTERNS:
        for match in pattern.finditer(body):
            name = match.group(1).lower().strip("/")
            version = match.group(2).strip("/")
            key = f"{name}@{version}"
            if key not in seen:
                seen.add(key)
                dependencies.append({
                    "name": name,
                    "version": version,
                    "source": cdn_name,
                    "type": "cdn",
                })

    for pattern, lib_name in LIB_PATTERNS:
        for match in pattern.finditer(body):
            version = match.group(1).strip()
            key = f"{lib_name}@{version}"
            if key not in seen:
                seen.add(key)
                dependencies.append({
                    "name": lib_name,
                    "version": version,
                    "source": "html_comment",
                    "type": "library",
                })

    cve_db = _load_cve_database()
    vuln_map = {}
    for cve in cve_db.get("cves", []):
        comp = cve.get("component", "").lower()
        if comp not in vuln_map:
            vuln_map[comp] = []
        vuln_map[comp].append(cve)

    for dep in dependencies:
        dep_name = dep["name"].lower()
        dep_version = dep["version"]
        matching_cves = []
        for cve in vuln_map.get(dep_name, []):
            affected = cve.get("affected_versions", [])
            if not affected or _version_matches(dep_version, affected):
                matching_cves.append({
                    "id": cve["id"],
                    "severity": cve.get("severity", "MEDIUM"),
                    "title": cve.get("title", ""),
                    "solution": cve.get("solution", "Update to latest version"),
                })
        dep["vulnerabilities"] = matching_cves
        dep["risk"] = "CRITICAL" if any(v["severity"] == "CRITICAL" for v in matching_cves) else "HIGH" if any(v["severity"] == "HIGH" for v in matching_cves) else "LOW"

    return {
        "dependencies": dependencies,
        "total": len(dependencies),
        "vulnerable": sum(1 for d in dependencies if d.get("vulnerabilities")),
        "sensitive_config_paths": SENSITIVE_CONFIG_FILES,
    }


def _version_matches(version: str, affected: list) -> bool:
    try:
        parts = [int(x) for x in version.split(".")[:3]]
    except Exception:
        return True
    for a in affected:
        if a.startswith("<="):
            try:
                ap = [int(x) for x in a[2:].split(".")[:3]]
                if parts <= ap:
                    return True
            except Exception:
                pass
        elif a.startswith("<"):
            try:
                ap = [int(x) for x in a[1:].split(".")[:3]]
                if parts < ap:
                    return True
            except Exception:
                pass
        elif version == a:
            return True
    return False


def _load_cve_database() -> dict:
    cve_file = BASE_DIR / "data" / "cves.json"
    if cve_file.exists():
        with open(cve_file) as f:
            return json.load(f)
    return {"cves": []}
