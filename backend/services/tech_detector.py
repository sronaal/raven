import json
import re
from pathlib import Path
from config.settings import BASE_DIR

def load_technologies() -> dict:
    tech_file = BASE_DIR / "data" / "technologies.json"
    if tech_file.exists():
        with open(tech_file) as f:
            return json.load(f)
    return {"servers": [], "languages": [], "cms": [], "libraries": [], "frameworks": []}

def detect_technologies(headers: dict, body: str) -> list:
    technologies = load_technologies()
    detected = []

    for category in ["servers", "languages", "cms", "libraries", "frameworks"]:
        for tech in technologies.get(category, []):
            for signature in tech.get("signatures", []):
                found_in = None
                if signature.lower() in json.dumps(headers).lower():
                    found_in = "headers"
                elif signature.lower() in body.lower():
                    found_in = "body"

                if found_in:
                    version = extract_version(signature, headers, body)
                    detected.append({
                        "name": tech["name"],
                        "version": version,
                        "type": tech.get("type", category),
                        "confidence": tech.get("confidence", "medium"),
                        "found_in": found_in,
                    })
                    break

    return detected

def extract_version(signature: str, headers: dict, body: str) -> str | None:
    header_str = json.dumps(headers)
    patterns = [
        rf"{re.escape(signature)}\s*[/v]?([\d.]+)",
        rf"{re.escape(signature)}-([\d.]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, header_str, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1)
    return None
