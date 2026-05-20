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
