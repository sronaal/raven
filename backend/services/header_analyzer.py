import re

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

CACHE_HEADERS = ["Cache-Control", "Pragma", "Expires"]

def analyze_headers(headers: dict) -> dict:
    configured_correctly = []
    missing_critical = []
    problematic = []

    all_headers = [{"name": k, "value": v} for k, v in headers.items()]

    for header_name, info in SECURITY_HEADERS.items():
        found = False
        for key in headers:
            if key.lower() == header_name.lower():
                value_eval = evaluate_security_header_value(header_name, headers[key])
                configured_correctly.append({
                    "name": key,
                    "value": headers[key],
                    "description": info["description"],
                    "value_evaluation": value_eval,
                })
                found = True
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

    cors_analysis = analyze_cors(headers)
    if cors_analysis.get("issues"):
        problematic.extend(cors_analysis["issues"])

    cache_analysis = analyze_cache_headers(headers)

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
            session_match = re.search(r'expires=([^;]+)', cookie_val, re.IGNORECASE)
            if session_match:
                issues.append("Persistent cookie (non-session)")
            else:
                if not any("Missing" in i for i in issues):
                    pass
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
        "cors": cors_analysis,
        "cache_headers": cache_analysis,
        "all_headers": all_headers,
        "score": score,
    }

def evaluate_security_header_value(name: str, value: str) -> dict:
    name_lower = name.lower()
    if name_lower == "x-frame-options":
        if value.upper() in ("DENY", "SAMEORIGIN"):
            return {"status": "good", "message": "Properly configured"}
        return {"status": "warning", "message": f"Unusual value: {value}"}
    if name_lower == "strict-transport-security":
        max_age = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
        if max_age:
            age = int(max_age.group(1))
            if age >= 31536000:
                has_sub = "includesubdomains" in value.lower()
                has_preload = "preload" in value.lower()
                return {"status": "good", "message": f"max-age={age}s{' + includeSubDomains' if has_sub else ''}{' + preload' if has_preload else ''}"}
            return {"status": "warning", "message": f"max-age={age}s is too short (min 31536000)"}
        return {"status": "warning", "message": "No max-age directive found"}
    if name_lower == "content-security-policy":
        if "unsafe-inline" in value.lower():
            return {"status": "warning", "message": "Uses unsafe-inline, reduces XSS protection"}
        if "unsafe-eval" in value.lower():
            return {"status": "warning", "message": "Uses unsafe-eval, reduces XSS protection"}
        if "*" in value and "default-src" in value.lower():
            return {"status": "warning", "message": "Wildcard in default-src weakens CSP"}
        return {"status": "good", "message": "CSP configured"}
    if name_lower == "x-content-type-options":
        if value.lower() == "nosniff":
            return {"status": "good", "message": "Properly configured"}
        return {"status": "warning", "message": f"Unusual value: {value}"}
    if name_lower == "referrer-policy":
        good_policies = ["no-referrer", "strict-origin-when-cross-origin", "same-origin"]
        if value.lower() in good_policies:
            return {"status": "good", "message": f"Strict policy: {value}"}
        return {"status": "warning", "message": f"Permissive policy: {value}"}
    return {"status": "info", "message": f"Present: {value[:50]}"}

def analyze_cors(headers: dict) -> dict:
    cors_info = {}
    issues = []

    for key in headers:
        if key.lower() == "access-control-allow-origin":
            cors_info["allow_origin"] = headers[key]
            if headers[key] == "*":
                issues.append({
                    "name": key,
                    "value": headers[key],
                    "risk": "CORS misconfiguration - allows any origin",
                    "recommendation": "Restrict to specific trusted origins instead of *",
                })
            break

    for key in headers:
        if key.lower() == "access-control-allow-credentials":
            cors_info["allow_credentials"] = headers[key]
            if headers.get("access-control-allow-origin", "") == "*" and headers[key].lower() == "true":
                issues.append({
                    "name": "Access-Control-Allow-Credentials",
                    "value": headers[key],
                    "risk": "CRITICAL - credentials with wildcard origin",
                    "recommendation": "Cannot use wildcard origin with credentials",
                })
            break

    for key in headers:
        if key.lower() == "access-control-allow-methods":
            cors_info["allow_methods"] = headers[key]
            break

    for key in headers:
        if key.lower() == "access-control-allow-headers":
            cors_info["allow_headers"] = headers[key]
            break

    if not cors_info:
        return {"enabled": False, "issues": []}

    return {"enabled": True, **cors_info, "issues": issues}

def analyze_cache_headers(headers: dict) -> dict:
    cache_info = {}
    for cache_h in CACHE_HEADERS:
        for key in headers:
            if key.lower() == cache_h.lower():
                cache_info[cache_h] = headers[key]
                break

    issues = []
    cc = cache_info.get("Cache-Control", "").lower()
    if "no-store" not in cc and "private" not in cc and cc:
        issues.append("Sensitive data may be cached (no no-store/private directive)")
    if "no-cache" in cc and "no-store" not in cc:
        issues.append("Using no-cache without no-store may still cache sensitive data")

    return {
        "headers": cache_info,
        "issues": issues,
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
