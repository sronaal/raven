import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def check_compliance(headers: dict, body: str, ssl_analysis: dict, url: str) -> dict:
    return {
        "gdpr": _check_gdpr(headers, body),
        "pci_dss": _check_pci_dss(headers, ssl_analysis),
        "hipaa": _check_hipaa(headers, ssl_analysis, body),
    }


def _check_gdpr(headers: dict, body: str) -> dict:
    checks = []
    body_lower = body.lower()

    has_cookie_consent = any(p in body_lower for p in ["cookie consent", "accept cookies", "cookie policy", "cookiebanner", "consent management"])
    checks.append({"requirement": "Cookie Consent", "passed": has_cookie_consent, "detail": "Cookie consent mechanism detected" if has_cookie_consent else "No cookie consent mechanism found"})

    has_privacy_policy = any(p in body_lower for p in ["privacy policy", "privacy notice", "data protection", "gdpr", "personal data"])
    checks.append({"requirement": "Privacy Policy", "passed": has_privacy_policy, "detail": "Privacy policy reference found" if has_privacy_policy else "No privacy policy reference found"})

    has_data_collection = any(p in body_lower for p in ["newsletter", "subscribe", "sign up", "register", "create account"])
    checks.append({"requirement": "Data Collection Disclosure", "passed": not has_data_collection or has_privacy_policy, "detail": "Data collection forms present with privacy policy" if has_data_collection and has_privacy_policy else "Data collection without visible privacy policy" if has_data_collection else "No data collection forms detected"})

    https = url_startswith_https(headers)
    checks.append({"requirement": "HTTPS for Data Transmission", "passed": https, "detail": "Site uses HTTPS" if https else "Site does not use HTTPS"})

    passed = sum(1 for c in checks if c["passed"])
    return {"score": round(passed / len(checks) * 100), "passed": passed, "total": len(checks), "checks": checks}


def _check_pci_dss(headers: dict, ssl_analysis: dict) -> dict:
    checks = []

    ssl_state = ssl_analysis.get("state", "")
    protocol = ssl_analysis.get("protocol", "")
    has_tls12 = "TLSv1.2" in protocol or "TLSv1.3" in protocol
    checks.append({"requirement": "TLS 1.2+ Required", "passed": has_tls12, "detail": f"Protocol: {protocol}"})

    hsts = False
    for k in headers:
        if k.lower() == "strict-transport-security":
            hsts = True
            break
    checks.append({"requirement": "HSTS Enabled", "passed": hsts, "detail": "HSTS header present" if hsts else "HSTS header missing"})

    cipher = ssl_analysis.get("cipher", {})
    has_strong_cipher = cipher.get("bits", 0) >= 128
    checks.append({"requirement": "Strong Cipher (128+ bits)", "passed": has_strong_cipher, "detail": f"Cipher: {cipher.get('name', 'N/A')} ({cipher.get('bits', 0)} bits)"})

    no_server_header = not any(k.lower() == "server" for k in headers)
    checks.append({"requirement": "Server Version Hidden", "passed": no_server_header, "detail": "Server header not exposed" if no_server_header else "Server header reveals version"})

    passed = sum(1 for c in checks if c["passed"])
    return {"score": round(passed / len(checks) * 100), "passed": passed, "total": len(checks), "checks": checks}


def _check_hipaa(headers: dict, ssl_analysis: dict, body: str) -> dict:
    checks = []

    ssl_available = ssl_analysis.get("available", False)
    checks.append({"requirement": "Encryption in Transit", "passed": ssl_available, "detail": "SSL/TLS available" if ssl_available else "No SSL/TLS"})

    protocol = ssl_analysis.get("protocol", "")
    has_strong_tls = "TLSv1.2" in protocol or "TLSv1.3" in protocol
    checks.append({"requirement": "Strong TLS Protocol", "passed": has_strong_tls, "detail": f"Protocol: {protocol}"})

    has_security_headers = any(k.lower() in ("strict-transport-security", "content-security-policy", "x-content-type-options") for k in headers)
    checks.append({"requirement": "Security Headers", "passed": has_security_headers, "detail": "Security headers configured" if has_security_headers else "Missing security headers"})

    has_audit = any(p in body.lower() for p in ["audit log", "access log", "activity log", "compliance"])
    checks.append({"requirement": "Audit Logging Reference", "passed": has_audit, "detail": "Audit logging mentioned" if has_audit else "No audit logging reference found"})

    passed = sum(1 for c in checks if c["passed"])
    return {"score": round(passed / len(checks) * 100), "passed": passed, "total": len(checks), "checks": checks}


def url_startswith_https(url):
    parsed = urlparse(url)
    return parsed.scheme == "https"
