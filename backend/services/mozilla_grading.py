def calculate_mozilla_grade(header_analysis: dict, ssl_analysis: dict, vuln_score: int) -> dict:
    grade = 100
    deductions = []
    details = []

    missing = header_analysis.get("missing_critical", [])
    configured = {h["name"]: h for h in header_analysis.get("configured_correctly", [])}
    missing_names = {m["name"] for m in missing}

    header_deductions = {
        "Content-Security-Policy": (15, "Missing CSP"),
        "Strict-Transport-Security": (15, "Missing HSTS"),
        "X-Content-Type-Options": (5, "Missing X-Content-Type-Options"),
        "X-Frame-Options": (5, "Missing X-Frame-Options"),
        "Referrer-Policy": (3, "Missing Referrer-Policy"),
        "Permissions-Policy": (2, "Missing Permissions-Policy"),
        "Cross-Origin-Opener-Policy": (3, "Missing COOP"),
        "Cross-Origin-Embedder-Policy": (3, "Missing COEP"),
        "Cross-Origin-Resource-Policy": (2, "Missing CORP"),
    }

    for header, (deduction, reason) in header_deductions.items():
        if header in missing_names:
            grade -= deduction
            deductions.append(f"{reason}: -{deduction}")
            details.append({"header": header, "status": "missing", "impact": reason})

    csp_value = configured.get("Content-Security-Policy", {}).get("value", "")
    if csp_value:
        csp_issues = []
        if "'unsafe-inline'" in csp_value:
            grade -= 5
            csp_issues.append("unsafe-inline")
            deductions.append("CSP allows unsafe-inline: -5")
        if "'unsafe-eval'" in csp_value:
            grade -= 5
            csp_issues.append("unsafe-eval")
            deductions.append("CSP allows unsafe-eval: -5")
        if "'*'" in csp_value or "*:" in csp_value:
            grade -= 10
            csp_issues.append("wildcard sources")
            deductions.append("CSP uses wildcard sources: -10")
        if csp_issues:
            details.append({"header": "Content-Security-Policy", "status": "weak", "issues": csp_issues})
        else:
            details.append({"header": "Content-Security-Policy", "status": "strong"})

    hsts_value = configured.get("Strict-Transport-Security", {}).get("value", "")
    if hsts_value:
        if "max-age=" in hsts_value.lower():
            try:
                age = int(hsts_value.lower().split("max-age=")[1].split(";")[0].strip())
                if age < 31536000:
                    grade -= 5
                    deductions.append("HSTS max-age < 1 year: -5")
                    details.append({"header": "HSTS", "status": "weak", "max_age": age})
            except Exception:
                pass

    for p in header_analysis.get("problematic", []):
        risk = p.get("risk", "")
        if "CORS" in risk:
            grade -= 10
            deductions.append("CORS wildcard: -10")
            details.append({"issue": "CORS", "status": "misconfigured"})
        elif "Information disclosure" in risk:
            grade -= 3
            deductions.append("Info disclosure: -3")

    for cookie in header_analysis.get("cookie_issues", []):
        issue_count = len(cookie.get("issues", []))
        if issue_count > 0:
            grade -= issue_count * 5
            deductions.append(f"Cookie issues ({issue_count}): -{issue_count * 5}")

    ssl_state = ssl_analysis.get("state", "")
    if ssl_state == "insecure":
        grade -= 20
        deductions.append("Insecure SSL: -20")
    elif ssl_state == "expired":
        grade -= 15
        deductions.append("Expired SSL: -15")
    elif ssl_state == "weak":
        grade -= 10
        deductions.append("Weak SSL: -10")

    cipher = ssl_analysis.get("cipher", {})
    if cipher.get("bits", 0) and cipher["bits"] < 128:
        grade -= 10
        deductions.append(f"Weak cipher ({cipher['bits']} bits): -10")

    if vuln_score < 50:
        grade -= 15
        deductions.append("High vulnerability count: -15")
    elif vuln_score < 80:
        grade -= 5
        deductions.append("Moderate vulnerability count: -5")

    grade = max(0, min(100, grade))

    if grade >= 95: letter = "A+"
    elif grade >= 90: letter = "A"
    elif grade >= 80: letter = "B"
    elif grade >= 70: letter = "C"
    elif grade >= 60: letter = "D"
    else: letter = "F"

    return {"grade": letter, "score": grade, "deductions": deductions, "details": details}
