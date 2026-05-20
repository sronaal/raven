import base64
import json
import re
import logging

logger = logging.getLogger(__name__)


def analyze_cookie(cookie_str: str) -> dict:
    parts = cookie_str.split(";")
    name_value = parts[0].strip()
    attrs = {}

    if "=" in name_value:
        name, value = name_value.split("=", 1)
    else:
        name, value = name_value, ""

    for part in parts[1:]:
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.lower().strip()] = v.strip()
        else:
            attrs[part.lower().strip()] = True

    issues = []
    if "httponly" not in attrs:
        issues.append({"flag": "HttpOnly", "severity": "HIGH", "description": "Cookie accessible via JavaScript (XSS risk)"})
    if "secure" not in attrs:
        issues.append({"flag": "Secure", "severity": "HIGH", "description": "Cookie sent over unencrypted HTTP"})
    if "samesite" not in attrs:
        issues.append({"flag": "SameSite", "severity": "MEDIUM", "description": "No CSRF protection via SameSite"})
    elif attrs.get("samesite", "").lower() == "none" and "secure" not in attrs:
        issues.append({"flag": "SameSite=None without Secure", "severity": "HIGH", "description": "SameSite=None requires Secure flag"})

    decoded_value = None
    value_type = "plain"
    try:
        if re.match(r"^[A-Za-z0-9+/]+=*$", value) and len(value) > 10:
            decoded = base64.b64decode(value).decode("utf-8", errors="ignore")
            if decoded.isprintable():
                decoded_value = decoded
                value_type = "base64"
    except Exception:
        pass

    if re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", value):
        value_type = "jwt"
        try:
            payload = value.split(".")[1]
            decoded_value = json.loads(base64.urlsafe_b64decode(payload + "=="))
        except Exception:
            pass

    suspicious_names = ["session", "token", "auth", "jwt", "sid", "phpsessid", "connect.sid", "jsessionid"]
    is_sensitive = any(s in name.lower() for s in suspicious_names)

    return {
        "name": name,
        "value": value[:100] if len(value) > 100 else value,
        "value_type": value_type,
        "decoded_value": decoded_value,
        "is_sensitive": is_sensitive,
        "flags": {
            "httponly": "httponly" in attrs,
            "secure": "secure" in attrs,
            "samesite": attrs.get("samesite", "not set"),
            "domain": attrs.get("domain", "not set"),
            "path": attrs.get("path", "/"),
            "expires": attrs.get("expires", attrs.get("max-age", "session")),
        },
        "issues": issues,
        "risk": "HIGH" if any(i["severity"] == "HIGH" for i in issues) else "MEDIUM" if issues else "LOW",
    }
