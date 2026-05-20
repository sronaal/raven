def calculate_mozilla_grade(header_analysis: dict, ssl_analysis: dict, vuln_score: int) -> dict:
    grade = 100
    deductions = []

    missing = header_analysis.get("missing_critical", [])
    critical_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
    for h in critical_headers:
        if not any(m["name"] == h for m in missing):
            pass
        else:
            if h == "Content-Security-Policy":
                grade -= 15
                deductions.append("Missing CSP: -15")
            elif h == "Strict-Transport-Security":
                grade -= 15
                deductions.append("Missing HSTS: -15")
            elif h == "X-Content-Type-Options":
                grade -= 5
                deductions.append("Missing X-Content-Type-Options: -5")
            elif h == "X-Frame-Options":
                grade -= 5
                deductions.append("Missing X-Frame-Options: -5")

    for p in header_analysis.get("problematic", []):
        risk = p.get("risk", "")
        if "CORS" in risk:
            grade -= 10
            deductions.append("CORS wildcard: -10")
        elif "Information disclosure" in risk:
            grade -= 3
            deductions.append("Info disclosure: -3")

    for cookie in header_analysis.get("cookie_issues", []):
        grade -= len(cookie.get("issues", [])) * 5
        deductions.append(f"Cookie issues: -{len(cookie['issues']) * 5}")

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

    return {"grade": letter, "score": grade, "deductions": deductions}
