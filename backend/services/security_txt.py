import asyncio
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

SECURITY_TXT_PATHS = ["/.well-known/security.txt", "/security.txt"]

KNOWN_FIELD_NAMES = [
    "acknowledgments",
    "canonical",
    "contact",
    "encryption",
    "expires",
    "hiring",
    "policy",
    "preferred-languages",
]


async def check_security_txt(base_url: str) -> dict:
    import httpx

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for path in SECURITY_TXT_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    content = response.text
                    parsed = _parse_security_txt(content)
                    return {
                        "found": True,
                        "url": url,
                        "content_type": response.headers.get("content-type", ""),
                        "fields": parsed["fields"],
                        "valid": parsed["valid"],
                        "missing_required": parsed["missing_required"],
                        "issues": parsed["issues"],
                    }
            except Exception as e:
                logger.debug("security.txt fetch error for %s: %s", url, e)

    return {
        "found": False,
        "url": None,
        "content_type": None,
        "fields": [],
        "valid": False,
        "missing_required": ["Contact"],
        "issues": ["No security.txt file found"],
    }


def _parse_security_txt(content: str) -> dict:
    fields = []
    valid = True
    missing_required = []
    issues = []

    lines = content.split("\n")
    has_contact = False
    has_expires = False

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            field_name = None
            for known in KNOWN_FIELD_NAMES:
                if key == known:
                    field_name = known
                    break

            if field_name:
                fields.append({"field": field_name, "value": value, "line": line})
                if field_name == "contact":
                    has_contact = True
                    _validate_contact(value, issues)
                elif field_name == "expires":
                    has_expires = True
                elif field_name == "encryption":
                    if not value.startswith("dns:") and not value.startswith("https://"):
                        issues.append(f"Encryption field should use dns: or https: URI: {value}")
                elif field_name == "canonical":
                    if not value.startswith("https://"):
                        issues.append(f"Canonical URL should use HTTPS: {value}")
            else:
                fields.append({"field": key, "value": value, "line": line, "unknown": True})
        elif line:
            fields.append({"field": "unparsed", "value": line, "line": line, "unknown": True})

    if not has_contact:
        missing_required.append("Contact")
        valid = False
    if not has_expires:
        missing_required.append("Expires")
        valid = False

    return {
        "fields": fields,
        "valid": valid and len(missing_required) == 0,
        "missing_required": missing_required,
        "issues": issues,
    }


def _validate_contact(value: str, issues: list):
    if not (value.startswith("http://") or value.startswith("https://") or value.startswith("mailto:") or value.startswith("tel:")):
        issues.append(f"Contact should use https:, mailto:, or tel: URI scheme: {value}")
