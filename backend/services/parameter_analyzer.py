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

def analyze_parameters(url: str, headers: dict, body: str) -> dict:
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    path_segments = [s for s in parsed.path.split("/") if s]

    parameters = []
    xss_vectors = []
    other_risks = []

    for param_name, values in query_params.items():
        param_info = analyze_single_parameter(param_name, values[0] if values else "")
        parameters.append(param_info)

        if param_name.lower() in XSS_PRONE_NAMES:
            xss_vectors.append({
                "parameter": param_name,
                "type": "Reflected",
                "risk": "HIGH",
                "payload_test": "<script>alert(1)</script>",
                "description": f"Parameter '{param_name}' may reflect user input in HTML response",
            })

        if param_name.lower() in PATH_TRAVERSAL_NAMES:
            other_risks.append({
                "type": "Path Traversal",
                "parameter": param_name,
                "risk": "HIGH",
                "description": f"Parameter '{param_name}' could be vulnerable to path traversal",
                "test_payload": "../../../etc/passwd",
                "mitigation": "Validate and sanitize file paths, use allowlists",
            })

        if param_name.lower() in OPEN_REDIRECT_NAMES:
            other_risks.append({
                "type": "Open Redirect",
                "parameter": param_name,
                "risk": "MEDIUM",
                "description": f"Parameter '{param_name}' could allow open redirect attacks",
                "test_payload": "https://evil.com",
                "mitigation": "Use allowlist of valid redirect URLs",
            })

        if param_name.lower() in SSRF_PRONE_NAMES:
            other_risks.append({
                "type": "SSRF",
                "parameter": param_name,
                "risk": "HIGH",
                "description": f"Parameter '{param_name}' could be vulnerable to Server-Side Request Forgery",
                "test_payload": "http://169.254.169.254/latest/meta-data/",
                "mitigation": "Validate URLs, block internal IP ranges, use allowlists",
            })

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
        "path_parameters": [{"name": f"segment_{i}", "value": seg} for i, seg in enumerate(path_segments)],
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
        tests = ["../../../etc/passwd", "..\\..\\windows\\system32"]
        mitigation = "Validate file paths, use allowlists, chroot"

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

def calculate_parameter_score(parameters: list, xss_vectors: list, other_risks: list) -> int:
    if not parameters and not xss_vectors and not other_risks:
        return 100

    score = 100
    for param in parameters:
        if param.get("risk") == "HIGH":
            score -= 10
        elif param.get("risk") == "MEDIUM":
            score -= 5

    for vector in xss_vectors:
        if vector.get("risk") == "CRITICAL":
            score -= 20
        elif vector.get("risk") == "HIGH":
            score -= 15

    for risk in other_risks:
        if risk.get("risk") == "HIGH":
            score -= 15
        elif risk.get("risk") == "MEDIUM":
            score -= 8

    return max(0, min(100, score))
