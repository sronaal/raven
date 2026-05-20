import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin", "/dashboard", "/manage", "/panel", "/console", "/cpanel"]
SENSITIVE_FILES = ["/.env", "/.git/config", "/.git/HEAD", "/wp-config.php", "/config.php", "/database.yml",
                   "/phpinfo.php", "/info.php", "/test.php", "/debug", "/.htpasswd", "/backup.sql", "/dump.sql"]
LOGIN_PATTERNS = ["login", "signin", "auth", "session", "password", "username", "email", "csrf_token", "_token"]
DEBUG_PATTERNS = ["stack trace", "traceback", "debug mode", "error detail", "exception", "at line ", "file "]


def check_owasp_top10(headers: dict, body: str, url: str, technologies: list, vulnerabilities: list, ssl_analysis: dict, parameter_analysis: dict) -> dict:
    categories = {
        "A01_broken_access_control": _check_a01(headers, body, url),
        "A02_cryptographic_failures": _check_a02(headers, ssl_analysis),
        "A03_injection": _check_a03(body, parameter_analysis),
        "A04_insecure_design": _check_a04(headers, body),
        "A05_security_misconfiguration": _check_a05(headers, body, url),
        "A06_vulnerable_components": _check_a06(technologies, vulnerabilities),
        "A07_auth_failures": _check_a07(body, headers),
        "A08_data_integrity": _check_a08(headers, body),
        "A09_logging_failures": _check_a09(body),
        "A10_ssrf": _check_a10(parameter_analysis),
    }

    overall_score = sum(c["score"] for c in categories.values()) / len(categories)

    return {
        "categories": categories,
        "overall_score": round(overall_score, 1),
        "risk_level": "CRITICAL" if overall_score < 30 else "HIGH" if overall_score < 50 else "MEDIUM" if overall_score < 70 else "LOW",
        "total_findings": sum(len(c["findings"]) for c in categories.values()),
    }


def _score(findings: list) -> int:
    if not findings:
        return 100
    deductions = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
    total = sum(deductions.get(f.get("severity", "INFO"), 1) for f in findings)
    return max(0, min(100, 100 - total))


def _check_a01(headers: dict, body: str, url: str) -> dict:
    findings = []
    cors = headers.get("Access-Control-Allow-Origin", "")
    if cors == "*":
        findings.append({"severity": "HIGH", "title": "CORS allows all origins", "description": "Access-Control-Allow-Origin is set to wildcard, allowing any domain to make requests", "remediation": "Restrict CORS to specific trusted origins"})

    parsed = urlparse(url)
    for path in ADMIN_PATHS:
        if path.lower() in body.lower():
            findings.append({"severity": "MEDIUM", "title": f"Admin panel reference found: {path}", "description": "Reference to administrative interface detected in page content", "remediation": "Ensure admin panels are protected with strong authentication and IP restrictions"})
            break

    for sf in SENSITIVE_FILES:
        if sf.lower() in body.lower():
            findings.append({"severity": "HIGH", "title": f"Sensitive file reference: {sf}", "description": "Reference to sensitive configuration or data file found", "remediation": "Remove references to sensitive files from public HTML"})
            break

    return {"score": _score(findings), "findings": findings, "name": "A01 - Broken Access Control"}


def _check_a02(headers: dict, ssl_analysis: dict) -> dict:
    findings = []
    hsts = False
    for k in headers:
        if k.lower() == "strict-transport-security":
            hsts = True
            val = headers[k].lower()
            if "max-age" in val:
                try:
                    age = int(val.split("max-age=")[1].split(";")[0].strip())
                    if age < 31536000:
                        findings.append({"severity": "MEDIUM", "title": "HSTS max-age too low", "description": f"HSTS max-age is {age}s, recommended minimum is 31536000s (1 year)", "remediation": "Set HSTS max-age to at least 31536000 seconds"})
                except Exception:
                    pass
            if "includesubdomains" not in val:
                findings.append({"severity": "LOW", "title": "HSTS missing includeSubDomains", "description": "HSTS header does not include subdomains", "remediation": "Add includeSubDomains to HSTS header"})
            break

    if not hsts:
        findings.append({"severity": "HIGH", "title": "HSTS header missing", "description": "HTTP Strict-Transport-Security header is not set", "remediation": "Add Strict-Transport-Security header with max-age >= 31536000"})

    ssl_state = ssl_analysis.get("state", "")
    if ssl_state == "insecure":
        findings.append({"severity": "CRITICAL", "title": "Insecure SSL/TLS configuration", "description": "Server uses deprecated SSL/TLS protocol version", "remediation": "Upgrade to TLS 1.2 or TLS 1.3"})
    elif ssl_state == "weak":
        findings.append({"severity": "HIGH", "title": "Weak SSL/TLS protocol", "description": "Server supports TLS 1.1 or older protocol", "remediation": "Disable TLS 1.0 and 1.1, use TLS 1.2+"})

    cipher = ssl_analysis.get("cipher", {})
    bits = cipher.get("bits", 0)
    if bits and bits < 128:
        findings.append({"severity": "HIGH", "title": f"Weak cipher key size: {bits} bits", "description": "SSL cipher uses less than 128-bit key", "remediation": "Use ciphers with at least 128-bit key size"})

    return {"score": _score(findings), "findings": findings, "name": "A02 - Cryptographic Failures"}


def _check_a03(body: str, parameter_analysis: dict) -> dict:
    findings = []
    params = parameter_analysis.get("parameters", [])
    for p in params:
        if p.get("risk") == "HIGH":
            findings.append({"severity": "HIGH", "title": f"High-risk parameter: {p['name']}", "description": f"Parameter may be vulnerable to: {', '.join(p.get('risks', []))}", "remediation": p.get("mitigation", "Implement input validation and parameterized queries")})

    xss_vectors = parameter_analysis.get("xss_vectors", [])
    if xss_vectors:
        findings.append({"severity": "HIGH", "title": f"{len(xss_vectors)} XSS vector(s) identified", "description": "Parameters detected that may reflect user input in HTML response", "remediation": "Implement output encoding and Content-Security-Policy header"})

    csp = False
    return {"score": _score(findings), "findings": findings, "name": "A03 - Injection"}


def _check_a04(headers: dict, body: str) -> dict:
    findings = []
    csrf = False
    for pattern in ["csrf_token", "_csrf", "csrfmiddlewaretoken", "authenticity_token"]:
        if pattern in body.lower():
            csrf = True
            break
    for k in headers:
        if k.lower() == "set-cookie" and "samesite" in headers[k].lower():
            csrf = True
            break
    if not csrf:
        findings.append({"severity": "MEDIUM", "title": "No CSRF protection detected", "description": "No CSRF tokens or SameSite cookie attributes found", "remediation": "Implement CSRF tokens for state-changing operations and set SameSite cookie attribute"})

    return {"score": _score(findings), "findings": findings, "name": "A04 - Insecure Design"}


def _check_a05(headers: dict, body: str, url: str) -> dict:
    findings = []
    security_headers = {
        "X-Frame-Options": ("MEDIUM", "Missing X-Frame-Options header allows clickjacking"),
        "Content-Security-Policy": ("HIGH", "Missing Content-Security-Policy allows XSS and injection"),
        "X-Content-Type-Options": ("MEDIUM", "Missing X-Content-Type-Options allows MIME sniffing"),
        "Referrer-Policy": ("LOW", "Missing Referrer-Policy may leak sensitive URLs"),
        "Permissions-Policy": ("LOW", "Missing Permissions-Policy allows unrestricted browser features"),
    }
    for header, (sev, desc) in security_headers.items():
        found = any(k.lower() == header.lower() for k in headers)
        if not found:
            findings.append({"severity": sev, "title": f"Missing {header}", "description": desc, "remediation": f"Add {header} header"})

    for k in headers:
        if k.lower() == "server":
            findings.append({"severity": "LOW", "title": "Server header exposes version", "description": f"Server header reveals: {headers[k]}", "remediation": "Remove or obfuscate Server header"})
        if k.lower() == "x-powered-by":
            findings.append({"severity": "LOW", "title": "X-Powered-By header exposes technology", "description": f"Technology revealed: {headers[k]}", "remediation": "Remove X-Powered-By header"})

    for pattern in DEBUG_PATTERNS:
        if pattern.lower() in body.lower():
            findings.append({"severity": "HIGH", "title": "Debug/error information exposed", "description": "Page content contains debug or error details", "remediation": "Disable debug mode in production and use generic error pages"})
            break

    return {"score": _score(findings), "findings": findings, "name": "A05 - Security Misconfiguration"}


def _check_a06(technologies: list, vulnerabilities: list) -> dict:
    findings = []
    for v in vulnerabilities:
        sev = v.get("severity", "MEDIUM")
        findings.append({"severity": sev, "title": f"Known vulnerability: {v['id']}", "description": v.get("description", "")[:200], "remediation": v.get("solution", "Update to latest version")})

    for tech in technologies:
        if tech.get("version"):
            findings.append({"severity": "INFO", "title": f"Detected {tech['name']} v{tech['version']}", "description": f"Technology identified via {tech.get('found_in', 'unknown')}", "remediation": "Keep all components updated to latest stable version"})

    return {"score": _score(findings), "findings": findings, "name": "A06 - Vulnerable and Outdated Components"}


def _check_a07(body: str, headers: dict) -> dict:
    findings = []
    has_login = any(p in body.lower() for p in ["login", "signin", "password", "username"])
    if has_login:
        cookie_issues = headers.get("cookie_issues", [])
        for k in headers:
            if k.lower() == "set-cookie":
                val = headers[k].lower()
                if "httponly" not in val:
                    findings.append({"severity": "HIGH", "title": "Session cookie missing HttpOnly", "description": "Session cookies accessible via JavaScript, vulnerable to XSS theft", "remediation": "Set HttpOnly flag on all session cookies"})
                if "secure" not in val:
                    findings.append({"severity": "HIGH", "title": "Session cookie missing Secure flag", "description": "Session cookies sent over unencrypted HTTP", "remediation": "Set Secure flag on all session cookies"})
                break

        if not any("rate-limit" in k.lower() or "x-ratelimit" in k.lower() for k in headers):
            findings.append({"severity": "MEDIUM", "title": "No rate limiting headers detected", "description": "No evidence of rate limiting on login endpoint", "remediation": "Implement rate limiting on authentication endpoints"})

    return {"score": _score(findings), "findings": findings, "name": "A07 - Identification and Authentication Failures"}


def _check_a08(headers: dict, body: str) -> dict:
    findings = []
    csp = None
    for k in headers:
        if k.lower() == "content-security-policy":
            csp = headers[k]
            break

    if csp:
        if "'unsafe-inline'" in csp:
            findings.append({"severity": "MEDIUM", "title": "CSP allows unsafe-inline scripts", "description": "Content-Security-Policy includes 'unsafe-inline', weakening XSS protection", "remediation": "Remove 'unsafe-inline' and use nonces or hashes for inline scripts"})
        if "'unsafe-eval'" in csp:
            findings.append({"severity": "MEDIUM", "title": "CSP allows unsafe-eval", "description": "Content-Security-Policy includes 'unsafe-eval', allows code injection", "remediation": "Remove 'unsafe-eval' from CSP"})
    else:
        findings.append({"severity": "HIGH", "title": "No Content-Security-Policy", "description": "Missing CSP header leaves application vulnerable to XSS and data injection", "remediation": "Implement a strict Content-Security-Policy"})

    sri_found = bool(re.findall(r'integrity\s*=\s*["\']sha', body, re.IGNORECASE))
    if not sri_found:
        findings.append({"severity": "LOW", "title": "No Subresource Integrity (SRI) on external scripts", "description": "External scripts loaded without integrity checks", "remediation": "Add integrity attribute to <script> and <link> tags loading external resources"})

    return {"score": _score(findings), "findings": findings, "name": "A08 - Software and Data Integrity Failures"}


def _check_a09(body: str) -> dict:
    findings = []
    for pattern in DEBUG_PATTERNS:
        if pattern.lower() in body.lower():
            findings.append({"severity": "MEDIUM", "title": "Error details exposed in response", "description": "Response contains stack traces or error details that could aid attackers", "remediation": "Use generic error pages in production and log details server-side"})
            break

    if "log" in body.lower() and any(p in body.lower() for p in ["access", "error", "debug"]):
        findings.append({"severity": "LOW", "title": "Possible log file accessible", "description": "Page content suggests log files may be publicly accessible", "remediation": "Ensure log files are not accessible via web"})

    return {"score": _score(findings), "findings": findings, "name": "A09 - Security Logging and Monitoring Failures"}


def _check_a10(parameter_analysis: dict) -> dict:
    findings = []
    other_risks = parameter_analysis.get("other_risks", [])
    for risk in other_risks:
        if risk.get("type") == "SSRF":
            findings.append({"severity": "HIGH", "title": f"SSRF risk on parameter: {risk['parameter']}", "description": risk.get("description", ""), "remediation": risk.get("mitigation", "Validate URLs and block internal IP ranges")})

    params = parameter_analysis.get("parameters", [])
    for p in params:
        if "redirect" in p.get("name", "").lower() or "url" in p.get("name", "").lower():
            findings.append({"severity": "MEDIUM", "title": f"Possible SSRF/Open Redirect: {p['name']}", "description": "Parameter accepts URLs that could be used for SSRF attacks", "remediation": "Validate and whitelist allowed URLs, block internal IPs"})

    return {"score": _score(findings), "findings": findings, "name": "A10 - Server-Side Request Forgery"}
