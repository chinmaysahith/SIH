"""Stage 9 Forensic Reporting Router.

Provides endpoints to generate and retrieve forensic investigation reports
in JSON, printable HTML, and compiled PDF formats, as well as generation history.
"""

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import Case
from app.reporting.models import ForensicReport, ReportHistoryResponse
from app.reporting.service import generate_report, get_report_history

router = APIRouter(
    tags=["reporting"],
)


@router.get(
    "/{case_id}/report",
    response_model=ForensicReport,
    summary="Get structured forensic report (JSON)",
    description="Generates and returns the complete, structured, evidence-backed forensic report in JSON format.",
)
def get_case_report_json(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    try:
        report, _ = generate_report(case_id, "JSON", db)
        return report
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate JSON report: {str(exc)}",
        )


@router.get(
    "/{case_id}/report/html",
    response_class=HTMLResponse,
    summary="Get printable forensic report (HTML)",
    description="Generates and returns a self-contained, printable HTML forensic report suitable for browser viewing or saving.",
)
def get_case_report_html(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    try:
        html_content, _ = generate_report(case_id, "HTML", db)
        return HTMLResponse(content=html_content, status_code=200)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate HTML report: {str(exc)}",
        )


@router.get(
    "/{case_id}/report/pdf",
    summary="Download compiled forensic report (PDF)",
    description="Generates and streams a compiled, multi-page, court-ready PDF forensic report document.",
)
def get_case_report_pdf(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    try:
        pdf_bytes, _ = generate_report(case_id, "PDF", db)
        filename = f"{case_id}_forensic_report.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate PDF report: {str(exc)}",
        )


@router.get(
    "/{case_id}/reports",
    response_model=ReportHistoryResponse,
    summary="Get report generation history",
    description="Returns the history of all generated reports (JSON, HTML, PDF) for a case with timestamps and SHA-256 fingerprints.",
)
def get_case_report_history(
    case_id: str,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    return get_report_history(case_id, db)
