SECURITY_HEADERS = {
    "X-Frame-Options": {
        "risk": "HIGH",
        "description": "Protects against clickjacking attacks",
        "recommendation": "Set to DENY or SAMEORIGIN",
    },
    "Content-Security-Policy": {
        "risk": "HIGH",
        "description": "Prevents XSS and data injection attacks",
        "recommendation": "Implement a strict CSP policy",
    },
    "Strict-Transport-Security": {
        "risk": "HIGH",
        "description": "Enforces HTTPS connections",
        "recommendation": "Set to at least 31536000 seconds with includeSubDomains",
    },
    "X-Content-Type-Options": {
        "risk": "MEDIUM",
        "description": "Prevents MIME type sniffing",
        "recommendation": "Set to nosniff",
    },
    "Referrer-Policy": {
        "risk": "MEDIUM",
        "description": "Controls referrer information sent with requests",
        "recommendation": "Set to strict-origin-when-cross-origin or no-referrer",
    },
    "Permissions-Policy": {
        "risk": "MEDIUM",
        "description": "Controls browser features availability",
        "recommendation": "Restrict unnecessary features",
    },
    "X-XSS-Protection": {
        "risk": "LOW",
        "description": "Legacy XSS filter (deprecated in modern browsers)",
        "recommendation": "Use CSP instead, but can set to 0",
    },
}

INFORMATION_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version",
]

def analyze_headers(headers: dict) -> dict:
    configured_correctly = []
    missing_critical = []
    problematic = []

    for header_name, info in SECURITY_HEADERS.items():
        found = False
        for key in headers:
            if key.lower() == header_name.lower():
                found = True
                configured_correctly.append({
                    "name": key,
                    "value": headers[key],
                    "description": info["description"],
                })
                break
        if not found:
            missing_critical.append({
                "name": header_name,
                "risk": info["risk"],
                "description": info["description"],
                "recommendation": info["recommendation"],
            })

    for header_name in INFORMATION_DISCLOSURE_HEADERS:
        for key in headers:
            if key.lower() == header_name.lower():
                problematic.append({
                    "name": key,
                    "value": headers[key],
                    "risk": "Information disclosure",
                    "recommendation": "Remove or obfuscate this header",
                })
                break

    cors_header = None
    for key in headers:
        if key.lower() == "access-control-allow-origin":
            cors_header = {"name": key, "value": headers[key]}
            if headers[key] == "*":
                problematic.append({
                    "name": key,
                    "value": headers[key],
                    "risk": "CORS misconfiguration - allows any origin",
                    "recommendation": "Restrict to specific trusted origins",
                })
            break

    cookie_headers = []
    for key in headers:
        if key.lower() == "set-cookie":
            cookie_val = headers[key]
            issues = []
            if "httponly" not in cookie_val.lower():
                issues.append("Missing HttpOnly flag")
            if "secure" not in cookie_val.lower():
                issues.append("Missing Secure flag")
            if "samesite" not in cookie_val.lower():
                issues.append("Missing SameSite attribute")
            if issues:
                cookie_headers.append({
                    "cookie": cookie_val[:100],
                    "issues": issues,
                    "risk": "HIGH" if len(issues) > 1 else "MEDIUM",
                })

    score = calculate_security_score(configured_correctly, missing_critical, problematic)

    return {
        "configured_correctly": configured_correctly,
        "missing_critical": missing_critical,
        "problematic": problematic,
        "cookie_issues": cookie_headers,
        "cors": cors_header,
        "score": score,
    }

def calculate_security_score(configured: list, missing: list, problematic: list) -> int:
    total_checks = len(configured) + len(missing)
    if total_checks == 0:
        return 0

    score = 0
    for _ in configured:
        score += 14

    risk_weights = {"HIGH": 15, "MEDIUM": 10, "LOW": 5}
    for item in missing:
        score -= risk_weights.get(item.get("risk", "MEDIUM"), 10)

    for _ in problematic:
        score -= 10

    return max(0, min(100, score))
