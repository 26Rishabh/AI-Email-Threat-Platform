# ─────────────────────────────────────────────
#  routers/report.py
#  PDF report generation endpoint.
#
#  ENDPOINT:
#    GET /api/report/{case_id}
#      — fetches the stored analysis from MongoDB,
#        generates a PDF on the fly using ReportLab,
#        and streams it back to the browser as a
#        downloadable file.
# ─────────────────────────────────────────────
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response

from database.connection import get_db
from modules.report_generator import generate_pdf_report

router = APIRouter(prefix="/api", tags=["Report"])


@router.get("/report/{case_id}")
async def get_forensic_report(case_id: str):
    """
    Generates and returns a PDF forensic report for a given case.

    The PDF is generated fresh every time (not cached) so it
    always reflects the latest data in the database.

    The browser receives it as an attachment — clicking the
    "Forensic Report" button in the dashboard triggers a download.
    """
    # Fetch the analysis from MongoDB
    db  = get_db()
    doc = db.analyses.find_one({"case_id": case_id}, {"_id": 0})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No analysis found for case ID: {case_id}",
        )

    # Generate the PDF bytes
    try:
        pdf_bytes = generate_pdf_report(doc)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {str(e)}",
        )

    # Return as a downloadable PDF file
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="forensic_report_{case_id}.pdf"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )
