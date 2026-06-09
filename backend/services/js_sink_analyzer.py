import re
import logging

logger = logging.getLogger(__name__)

DANGEROUS_SINKS = {
    "eval": {"risk": "CRITICAL", "cwe": "CWE-95", "desc": "eval() executes arbitrary code from a string"},
    "Function(": {"risk": "CRITICAL", "cwe": "CWE-95", "desc": "Function constructor executes arbitrary code from a string"},
    "setTimeout": {"risk": "MEDIUM", "cwe": "CWE-79", "desc": "setTimeout with string argument can execute arbitrary code"},
    "setInterval": {"risk": "MEDIUM", "cwe": "CWE-79", "desc": "setInterval with string argument can execute arbitrary code"},
    "document.write": {"risk": "HIGH", "cwe": "CWE-79", "desc": "document.write can inject arbitrary HTML"},
    "innerHTML": {"risk": "HIGH", "cwe": "CWE-79", "desc": "innerHTML assignment can execute XSS"},
    "outerHTML": {"risk": "HIGH", "cwe": "CWE-79", "desc": "outerHTML assignment can execute XSS"},
    "insertAdjacentHTML": {"risk": "HIGH", "cwe": "CWE-79", "desc": "insertAdjacentHTML can inject arbitrary HTML"},
    "location.href": {"risk": "MEDIUM", "cwe": "CWE-601", "desc": "location.href setter can cause open redirect"},
    "location.replace": {"risk": "MEDIUM", "cwe": "CWE-601", "desc": "location.replace can cause open redirect"},
    "location.assign": {"risk": "MEDIUM", "cwe": "CWE-601", "desc": "location.assign can cause open redirect"},
    "window.open": {"risk": "MEDIUM", "cwe": "CWE-601", "desc": "window.open with user input can cause open redirect"},
    "$.html": {"risk": "HIGH", "cwe": "CWE-79", "desc": "jQuery .html() can inject arbitrary HTML"},
    "$.append": {"risk": "HIGH", "cwe": "CWE-79", "desc": "jQuery .append() can inject arbitrary HTML"},
    "$.prepend": {"risk": "HIGH", "cwe": "CWE-79", "desc": "jQuery .prepend() can inject arbitrary HTML"},
    "$.before": {"risk": "MEDIUM", "cwe": "CWE-79", "desc": "jQuery .before() can inject arbitrary HTML"},
    "$.after": {"risk": "MEDIUM", "cwe": "CWE-79", "desc": "jQuery .after() can inject arbitrary HTML"},
    "$.replaceWith": {"risk": "HIGH", "cwe": "CWE-79", "desc": "jQuery .replaceWith() can inject arbitrary HTML"},
    "$.html(": {"risk": "HIGH", "cwe": "CWE-79", "desc": "jQuery $() with HTML string can create arbitrary elements"},
    "document.cookie": {"risk": "MEDIUM", "cwe": "CWE-79", "desc": "document.cookie setter can modify cookies"},
    "postMessage": {"risk": "MEDIUM", "cwe": "CWE-345", "desc": "postMessage should validate origin to avoid data leaks"},
    "JSON.parse": {"risk": "LOW", "cwe": "CWE-20", "desc": "JSON.parse on untrusted data can cause prototype pollution if not sanitized"},
    "localStorage.setItem": {"risk": "LOW", "cwe": "CWE-312", "desc": "Sensitive data in localStorage persists after session"},
    "sessionStorage.setItem": {"risk": "LOW", "cwe": "CWE-312", "desc": "Sensitive data in sessionStorage persists"},
    "WebSocket(": {"risk": "LOW", "cwe": "CWE-319", "desc": "WebSocket connections should use wss:// instead of ws://"},
}

DOM_PATTERNS = re.compile(
    r'(document\.(write|writeln)\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["\']|setInterval\s*\(\s*["\'])',
    re.IGNORECASE,
)

SAFE_PATTERNS = re.compile(
    r'(\.(textContent|innerText)\s*=|encodeURIComponent|sanitize|DOMPurify|escape|\.val\s*\()',
    re.IGNORECASE,
)


def analyze_js_sinks(body_content: str, script_urls: list[str] = None) -> dict:
    findings = []

    if not body_content:
        return {"sinks": [], "total": 0, "risk": "none"}

    lines = body_content.split("\n")
    contexts = {
        "inline_html": True,
        "inline_script": False,
        "external_script": False,
    }

    in_script = False
    script_content_lines = []

    for i, line in enumerate(lines):
        stripped = line.strip()
        line_number = i + 1

        if "<script" in stripped.lower() and "src=" in stripped.lower():
            contexts["external_script"] = True
        if "<script" in stripped.lower() and "src=" not in stripped.lower():
            in_script = True
            script_content_lines = []
            continue
        if in_script:
            if "</script>" in stripped:
                in_script = False
                for sink_name, info in DANGEROUS_SINKS.items():
                    for sline in script_content_lines:
                        line_idx = script_content_lines.index(sline)
                        if sink_name in sline and not SAFE_PATTERNS.search(sline):
                            findings.append({
                                "sink": sink_name,
                                "risk": info["risk"],
                                "cwe": info["cwe"],
                                "description": info["desc"],
                                "line": sline.strip()[:200],
                                "line_number": line_number - len(script_content_lines) + line_idx,
                                "context": "inline_script",
                            })
                            break
            elif in_script:
                script_content_lines.append(stripped)
        else:
            for sink_name, info in DANGEROUS_SINKS.items():
                if sink_name in stripped and not SAFE_PATTERNS.search(stripped):
                    dm = DOM_PATTERNS.search(stripped)
                    if dm or not any(x in stripped for x in [".js", '.css', "stylesheet", "preload"]):
                        findings.append({
                            "sink": sink_name,
                            "risk": info["risk"],
                            "cwe": info["cwe"],
                            "description": info["desc"],
                            "line": stripped[:200],
                            "line_number": line_number,
                            "context": "inline_html",
                        })

    unique_findings = []
    seen = set()
    for f in findings:
        key = (f["sink"], f["line"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    risk = "none"
    critical = sum(1 for f in unique_findings if f["risk"] == "CRITICAL")
    high = sum(1 for f in unique_findings if f["risk"] == "HIGH")
    if critical > 0:
        risk = "critical"
    elif high > 0:
        risk = "high"
    elif len(unique_findings) > 5:
        risk = "medium"

    return {
        "sinks": unique_findings[:50],
        "total": len(unique_findings),
        "risk": risk,
        "by_risk": {
            "CRITICAL": critical,
            "HIGH": high,
            "MEDIUM": sum(1 for f in unique_findings if f["risk"] == "MEDIUM"),
            "LOW": sum(1 for f in unique_findings if f["risk"] == "LOW"),
        },
    }
