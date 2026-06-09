import re
from urllib.parse import urlparse, parse_qs

SQLI_PRONE_NAMES = [
    "id", "user_id", "userid", "uid", "pid", "page_id", "cat_id", "category",
    "search", "query", "q", "keyword", "keywords", "term", "filter", "sort",
    "order", "orderby", "limit", "offset", "start", "end", "from", "to",
    "date", "year", "month", "day", "name", "title", "description", "content",
    "email", "username", "password", "login", "token", "session", "sid",
    "item", "product", "article", "post", "comment", "tag", "label",
    "num", "number", "count", "amount", "price", "cost", "total",
]

XSS_PRONE_NAMES = [
    "search", "q", "query", "keyword", "term", "input", "text", "name",
    "title", "comment", "message", "description", "content", "body",
    "username", "user", "email", "first_name", "last_name", "nickname",
    "redirect", "url", "next", "return", "dest", "destination", "goto",
    "callback", "jsonp", "ref", "referer", "source", "from", "page",
]

PATH_TRAVERSAL_NAMES = [
    "file", "path", "filepath", "document", "folder", "root", "dir",
    "directory", "include", "load", "template", "view", "layout",
    "style", "css", "image", "img", "src", "download", "attachment",
]

OPEN_REDIRECT_NAMES = [
    "url", "redirect", "redir", "next", "return", "dest", "destination",
    "goto", "link", "target", "out", "forward", "continue", "returnto",
    "return_url", "redirect_url", "redirect_uri", "redirect_to",
]

SSRF_PRONE_NAMES = [
    "url", "uri", "path", "continue", "data", "reference", "site",
    "html", "val", "validate", "domain", "callback", "fetch",
    "image", "img", "avatar", "photo", "proxy", "proxy_url",
    "source", "external", "remote", "load", "read", "open",
]

SENSITIVE_PARAM_NAMES = [
    "password", "pass", "pwd", "secret", "token", "api_key", "apikey",
    "key", "auth", "authorization", "bearer", "jwt", "session", "sid",
    "csrf", "credit", "card", "cc", "cvv", "ssn", "phone", "otp",
]

API_PATTERNS = [
    r'/api/v\d+/',
    r'/rest/',
    r'/graphql',
    r'/v\d+/',
]

def analyze_parameters(url: str, headers: dict, body: str) -> dict:
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    path_segments = [s for s in parsed.path.split("/") if s]

    parameters = []
    xss_vectors = []
    other_risks = []

    seen_params = {}
    for param_name, values in query_params.items():
        if param_name in seen_params:
            seen_params[param_name] += 1
        else:
            seen_params[param_name] = 1

        param_info = analyze_single_parameter(param_name, values[0] if values else "")
        parameters.append(param_info)

        if param_name.lower() in XSS_PRONE_NAMES:
            injection_context = determine_injection_context(param_name, values[0] if values else "", headers)
            xss_vectors.append({
                "parameter": param_name,
                "type": "Reflected",
                "risk": "HIGH",
                "payload_test": "<script>alert(1)</script>",
                "payloads": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "javascript:alert(1)",
                    "\"><script>alert(1)</script>",
                ],
                "description": f"Parameter '{param_name}' may reflect user input in HTML response",
                "injection_context": injection_context,
            })

        if param_name.lower() in PATH_TRAVERSAL_NAMES:
            other_risks.append({
                "type": "Path Traversal",
                "parameter": param_name,
                "risk": "HIGH",
                "description": f"Parameter '{param_name}' could be vulnerable to path traversal",
                "test_payload": "../../../etc/passwd",
                "payloads": [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32",
                    "%2e%2e%2f%2e%2e%2f",
                ],
                "mitigation": "Validate and sanitize file paths, use allowlists",
            })

        if param_name.lower() in OPEN_REDIRECT_NAMES:
            other_risks.append({
                "type": "Open Redirect",
                "parameter": param_name,
                "risk": "MEDIUM",
                "description": f"Parameter '{param_name}' could allow open redirect attacks",
                "test_payload": "https://evil.com",
                "payloads": [
                    "https://evil.com",
                    "//evil.com",
                    "https:evil.com",
                ],
                "mitigation": "Use allowlist of valid redirect URLs",
            })

        if param_name.lower() in SSRF_PRONE_NAMES:
            other_risks.append({
                "type": "SSRF",
                "parameter": param_name,
                "risk": "HIGH",
                "description": f"Parameter '{param_name}' could be vulnerable to Server-Side Request Forgery",
                "test_payload": "http://169.254.169.254/latest/meta-data/",
                "payloads": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://127.0.0.1:8080/admin",
                    "file:///etc/passwd",
                ],
                "mitigation": "Validate URLs, block internal IP ranges, use allowlists",
            })

    hpp_detected = {k: v for k, v in seen_params.items() if v > 1}
    if hpp_detected:
        other_risks.append({
            "type": "HTTP Parameter Pollution",
            "parameter": list(hpp_detected.keys()),
            "risk": "MEDIUM",
            "description": f"Duplicate parameters detected: {hpp_detected}. May allow HPP attacks.",
            "test_payload": "param=valid&param=malicious",
            "payloads": [],
            "mitigation": "Reject or deduplicate repeated parameters server-side",
        })

    path_analysis = analyze_path_parameters(path_segments)
    body_analysis = analyze_request_body(body, headers)

    csp_header = None
    for key in headers:
        if key.lower() == "content-security-policy":
            csp_header = headers[key]
            break

    if xss_vectors and not csp_header:
        for vector in xss_vectors:
            vector["risk"] = "CRITICAL"
            vector["description"] += " (No CSP header present)"

    score = calculate_parameter_score(parameters, xss_vectors, other_risks)

    return {
        "parameters": parameters,
        "xss_vectors": xss_vectors,
        "other_risks": other_risks,
        "path_parameters": path_analysis,
        "body_analysis": body_analysis,
        "hpp_detected": hpp_detected,
        "score": score,
    }

def analyze_single_parameter(name: str, value: str) -> dict:
    param_type = detect_parameter_type(value)
    risk_level = "LOW"
    risks = []
    tests = []
    mitigation = "Input validation and sanitization"

    if name.lower() in SQLI_PRONE_NAMES:
        risk_level = "HIGH"
        risks.append("SQL Injection possible")
        tests = ["1' OR '1'='1", "1; DROP TABLE users--", "1 UNION SELECT NULL--"]
        mitigation = "Use prepared statements / parameterized queries"

    elif name.lower() in XSS_PRONE_NAMES:
        risk_level = "HIGH"
        risks.append("XSS possible - parameter may reflect in response")
        tests = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        mitigation = "Encode output, implement CSP, validate input"

    elif name.lower() in PATH_TRAVERSAL_NAMES:
        risk_level = "HIGH"
        risks.append("Path Traversal possible")
        tests = ["../../../etc/passwd", "..\\..\\..\\windows\\system32"]
        mitigation = "Validate file paths, use allowlists, chroot"

    if name.lower() in SENSITIVE_PARAM_NAMES:
        risk_level = "CRITICAL"
        risks.append("Sensitive data in URL parameters (visible in logs, referrer)")
        mitigation = "Use POST body instead of URL parameters for sensitive data"

    if is_encoded(value):
        risks.append("Parameter appears to be encoded")

    return {
        "name": name,
        "location": "query_string",
        "data_type": param_type,
        "value_sample": value[:50] if value else "",
        "risk": risk_level,
        "risks": risks,
        "suggested_tests": tests,
        "mitigation": mitigation,
    }

def detect_parameter_type(value: str) -> str:
    if not value:
        return "empty"
    if re.match(r"^\d+$", value):
        return "integer"
    if re.match(r"^\d+\.\d+$", value):
        return "float"
    if re.match(r"^(true|false|0|1)$", value, re.IGNORECASE):
        return "boolean"
    if re.match(r"^[A-Za-z0-9+/]+=*$", value) and len(value) > 10:
        return "possible_base64"
    if re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", value):
        return "possible_jwt"
    if re.match(r"^[0-9a-f]{32}$", value, re.IGNORECASE):
        return "possible_hash_md5"
    if re.match(r"^[0-9a-f]{40}$", value, re.IGNORECASE):
        return "possible_hash_sha1"
    if "," in value:
        return "possible_array"
    return "string"

def is_encoded(value: str) -> bool:
    if not value:
        return False
    return "%" in value or "+" in value

def determine_injection_context(param_name: str, value: str, headers: dict) -> str:
    name_lower = param_name.lower()
    if name_lower in ("redirect", "url", "next", "return", "dest"):
        return "URL/redirect context"
    if name_lower in ("callback", "jsonp", "ref"):
        return "JavaScript callback context"
    if name_lower in ("name", "title", "comment", "message"):
        return "HTML element content"
    return "HTML attribute or script context"

def analyze_path_parameters(segments: list) -> list:
    path_params = []
    for i, seg in enumerate(segments):
        if re.match(r"^\d+$", seg):
            path_params.append({
                "position": i,
                "value": seg,
                "type": "numeric_id",
                "risk": "MEDIUM",
                "description": f"Numeric path segment at position {i} - may be an IDOR target",
            })
        elif re.match(r"^[0-9a-f]{8,}$", seg, re.IGNORECASE) and len(seg) >= 8:
            path_params.append({
                "position": i,
                "value": seg,
                "type": "hash_uuid",
                "risk": "LOW",
                "description": f"Hash/UUID segment at position {i}",
            })
        elif seg in ("admin", "api", "v1", "v2", "internal", "private", "debug"):
            path_params.append({
                "position": i,
                "value": seg,
                "type": "sensitive_path",
                "risk": "INFO",
                "description": f"Sensitive/reserved path segment at position {i}",
            })
    return path_params

def analyze_request_body(body: str, headers: dict) -> dict:
    content_type = None
    for key in headers:
        if key.lower() == "content-type":
            content_type = headers[key]
            break

    if not body and not content_type:
        return {"present": False, "content_type": None}

    analysis = {"present": bool(body), "content_type": content_type}

    if content_type:
        ct_lower = content_type.lower()
        if "json" in ct_lower:
            analysis["format"] = "JSON"
            analysis["description"] = "Expects JSON request body"
        elif "xml" in ct_lower:
            analysis["format"] = "XML"
            analysis["description"] = "Expects XML request body"
        elif "form" in ct_lower or "urlencoded" in ct_lower:
            analysis["format"] = "Form/URL-encoded"
            analysis["description"] = "Expects form data submission"
        elif "multipart" in ct_lower:
            analysis["format"] = "Multipart"
            analysis["description"] = "Expects multipart form (file upload possible)"
        else:
            analysis["format"] = "Other"
            analysis["description"] = f"Content type: {content_type}"

    if body:
        hidden_params = extract_hidden_params(body)
        if hidden_params:
            analysis["hidden_params"] = hidden_params

    return analysis

def extract_hidden_params(html_body: str) -> list:
    hidden = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', html_body, re.IGNORECASE)
    hidden += re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\']', html_body, re.IGNORECASE)
    return [{"name": h[0], "value": h[1][:50]} for h in hidden] if hidden else []

def calculate_parameter_score(parameters: list, xss_vectors: list, other_risks: list) -> int:
    if not parameters and not xss_vectors and not other_risks:
        return 100

    score = 100
    for param in parameters:
        if param.get("risk") == "CRITICAL":
            score -= 20
        elif param.get("risk") == "HIGH":
            score -= 10
        elif param.get("risk") == "MEDIUM":
            score -= 5

    for vector in xss_vectors:
        if vector.get("risk") == "CRITICAL":
            score -= 20
        elif vector.get("risk") == "HIGH":
            score -= 15

    for risk in other_risks:
        if risk.get("risk") == "CRITICAL":
            score -= 20
        elif risk.get("risk") == "HIGH":
            score -= 15
        elif risk.get("risk") == "MEDIUM":
            score -= 8

    return max(0, min(100, score))
