from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from services.scan_store import get_scans, get_scan_by_id, delete_scan, get_scan_stats
from services.pdf_report import generate_pdf_report

router = APIRouter()


@router.get("/scans")
async def list_scans(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return {"scans": get_scans(limit=limit, offset=offset)}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/scans/{scan_id}")
async def remove_scan(scan_id: int):
    if not delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted", "id": scan_id}


@router.get("/stats")
async def stats():
    return get_scan_stats()


@router.get("/scans/{scan_id}/report")
async def scan_report(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = scan.get("result_json", scan)
    pdf_bytes = generate_pdf_report(result)
    if not pdf_bytes:
        raise HTTPException(status_code=500, detail="PDF generation failed. Install weasyprint.")

    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.pdf"})


@router.get("/scans/compare")
async def compare_scans(id1: int = Query(...), id2: int = Query(...)):
    scan1 = get_scan_by_id(id1)
    scan2 = get_scan_by_id(id2)
    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    r1 = scan1.get("result_json", scan1)
    r2 = scan2.get("result_json", scan2)

    s1_total = r1.get("resumen_general", {}).get("total_score", scan1.get("total_score"))
    s2_total = r2.get("resumen_general", {}).get("total_score", scan2.get("total_score"))

    vulns1 = {v["id"] for v in r1.get("nivel2", {}).get("vulnerabilities", [])}
    vulns2 = {v["id"] for v in r2.get("nivel2", {}).get("vulnerabilities", [])}

    headers1 = {h["name"] for h in r1.get("nivel1", {}).get("headers", {}).get("configured_correctly", [])}
    headers2 = {h["name"] for h in r2.get("nivel1", {}).get("headers", {}).get("configured_correctly", [])}

    return {
        "scan1": {"id": id1, "url": scan1["url"], "timestamp": scan1["timestamp"], "total_score": s1_total},
        "scan2": {"id": id2, "url": scan2["url"], "timestamp": scan2["timestamp"], "total_score": s2_total},
        "score_delta": (s2_total or 0) - (s1_total or 0),
        "new_vulnerabilities": list(vulns2 - vulns1),
        "resolved_vulnerabilities": list(vulns1 - vulns2),
        "new_headers": list(headers2 - headers1),
        "removed_headers": list(headers1 - headers2),
    }
