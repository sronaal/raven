import io
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def generate_pdf_report(scan_data: dict) -> bytes:
    try:
        from weasyprint import HTML
    except ImportError:
        logger.error("weasyprint not installed")
        return b""

    url = scan_data.get("url", "Unknown")
    timestamp = scan_data.get("timestamp", "")
    resumen = scan_data.get("resumen_general", {})
    nivel1 = scan_data.get("nivel1", {})
    nivel2 = scan_data.get("nivel2", {})
    nivel3 = scan_data.get("nivel3", {})
    total_score = resumen.get("total_score", 0)

    score_color = "#10b981" if total_score >= 80 else "#22c55e" if total_score >= 60 else "#eab308" if total_score >= 40 else "#f97316" if total_score >= 20 else "#ef4444"

    vulns = nivel2.get("vulnerabilities", [])
    vuln_rows = ""
    for v in vulns[:20]:
        sev_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}.get(v.get("severity", ""), "#6b7280")
        vuln_rows += f"""<tr>
            <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:11px">{v.get('id', '')}</td>
            <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb"><span style="background:{sev_color};color:white;padding:2px 8px;border-radius:4px;font-size:10px">{v.get('severity', '')}</span></td>
            <td style="padding:6px 8px;border-bottom:1px solid #e5e7eb;font-size:11px">{v.get('title', '')[:80]}</td>
        </tr>"""

    missing_headers = nivel1.get("headers", {}).get("missing_critical", [])
    header_rows = ""
    for h in missing_headers:
        header_rows += f"""<tr>
            <td style="padding:4px 8px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:11px">{h.get('name', '')}</td>
            <td style="padding:4px 8px;border-bottom:1px solid #e5e7eb;font-size:11px">{h.get('recommendation', '')[:80]}</td>
        </tr>"""

    recs = resumen.get("priority_recommendations", [])
    rec_items = "".join(f"<li style='margin:4px 0;font-size:12px'>{r}</li>" for r in recs[:15])

    compliance = scan_data.get("compliance", {})
    compliance_sections = ""
    for framework, data in compliance.items():
        if isinstance(data, dict):
            ck = data.get("checks", [])
            ck_rows = ""
            for c in ck:
                icon = "✓" if c.get("passed") else "✗"
                color = "#16a34a" if c.get("passed") else "#dc2626"
                ck_rows += f"<tr><td style='padding:4px 8px;border-bottom:1px solid #e5e7eb;font-size:11px'>{icon}</td><td style='padding:4px 8px;border-bottom:1px solid #e5e7eb;font-size:11px'>{c.get('requirement', '')}</td><td style='padding:4px 8px;border-bottom:1px solid #e5e7eb;font-size:11px;color:{color}'>{c.get('detail', '')[:80]}</td></tr>"
            if ck_rows:
                compliance_sections += f"<h3>{framework.upper()}</h3><table><tr><th style='width:30px'>Status</th><th>Requirement</th><th>Detail</th></tr>{ck_rows}</table>"

    cookie_data = nivel3.get("cookies", nivel2.get("cookies", []))
    cookie_rows = ""
    for c in cookie_data[:15]:
        flags = c.get("flags", {})
        issues = c.get("issues", [])
        flag_str = " ".join(f"{k}={v}" for k, v in flags.items() if v)
        issue_str = ", ".join(issues[:3])
        cookie_rows += f"<tr><td style='padding:4px 8px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:11px'>{c.get('name', '')}</td><td style='padding:4px 8px;border-bottom:1px solid #e5e7eb;font-size:11px'>{flag_str}</td><td style='padding:4px 8px;border-bottom:1px solid #e5e7eb;font-size:11px;color:#dc2626'>{issue_str}</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; color: #1f2937; }}
    h1 {{ font-size: 24px; margin-bottom: 4px; }}
    h2 {{ font-size: 18px; margin-top: 24px; border-bottom: 2px solid #10b981; padding-bottom: 4px; }}
    h3 {{ font-size: 14px; margin-top: 16px; color: #374151; }}
    .meta {{ color: #6b7280; font-size: 13px; margin-bottom: 20px; }}
    .score-circle {{ width: 100px; height: 100px; border-radius: 50%; background: {score_color}; color: white; display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: bold; margin: 20px auto; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
    th {{ background: #f3f4f6; text-align: left; padding: 8px; font-size: 12px; }}
    .footer {{ margin-top: 40px; text-align: center; color: #9ca3af; font-size: 11px; border-top: 1px solid #e5e7eb; padding-top: 12px; }}
</style></head><body>
    <h1>URL Security Scan Report</h1>
    <div class="meta">URL: {url}<br>Date: {datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC') if timestamp else 'N/A'}</div>
    <div class="score-circle">{total_score}</div>
    <p style="text-align:center;color:#6b7280;font-size:13px">Overall Security Score</p>

    <h2>Score Breakdown</h2>
    <table><tr><th>Level</th><th>Score</th></tr>
    <tr><td>Level 1 - Fingerprinting</td><td>{nivel1.get('security_score', 'N/A')}</td></tr>
    <tr><td>Level 2 - Vulnerabilities</td><td>{nivel2.get('vulnerability_score', 'N/A')}</td></tr>
    <tr><td>Level 3 - Parameters</td><td>{nivel3.get('parameter_score', 'N/A')}</td></tr>
    </table>

    <h2>Vulnerabilities ({len(vulns)} found)</h2>
    {f'<table><tr><th>ID</th><th>Severity</th><th>Title</th></tr>{vuln_rows}</table>' if vuln_rows else '<p style="color:#16a34a">No vulnerabilities found.</p>'}

    <h2>Missing Security Headers</h2>
    {f'<table><tr><th>Header</th><th>Recommendation</th></tr>{header_rows}</table>' if header_rows else '<p style="color:#16a34a">All critical headers present.</p>'}

    {f'<h2>Cookie Security ({len(cookie_data)} cookies)</h2><table><tr><th>Name</th><th>Flags</th><th>Issues</th></tr>{cookie_rows}</table>' if cookie_rows else ''}

    {f'<h2>Compliance</h2>{compliance_sections}' if compliance_sections else ''}

    <h2>Recommendations</h2>
    <ul>{rec_items}</ul>

    <div class="footer">Generated by URL Security Scanner | For educational purposes only</div>
</body></html>"""

    pdf = HTML(string=html_content).write_pdf()
    return pdf
