from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, File, UploadFile, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.services.quarantine import process_and_quarantine_file
from app.services.queue import enqueue_case_analysis

router = APIRouter(prefix="", tags=["Upload"])


class CaseUploadResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    original_filename: str
    sha256: str
    file_size: int
    file_extension: str
    status: str
    job_id: Optional[str] = None
    error_message: Optional[str] = None
    upload_timestamp: datetime


@router.post(
    "/upload",
    response_model=CaseUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload email evidence to quarantine and enqueue for analysis",
    description=(
        "Receives a raw email file (.eml or .msg), preserves it byte-for-byte in the "
        "quarantine store, verifies its SHA-256 hash, registers the case in SQLite, and "
        "enqueues background analysis via Redis/RQ."
    ),
)
async def upload_email(
    file: UploadFile = File(..., description="Raw email file (.eml or .msg)"),
    db: Session = Depends(get_db),
):
    # 1. Preserve evidence byte-for-byte in quarantine and register in DB (Stage 1 invariant)
    case_record = await process_and_quarantine_file(file=file, db=db)

    # 2. Enqueue background analysis job (Stage 1.5)
    success, job_id, err_msg = enqueue_case_analysis(case_record.case_id)

    from app.audit import record_event, AuditEventType

    if success:
        case_record.status = "queued"
        case_record.queue_status = "queued"
        case_record.job_id = job_id
        case_record.error_message = None
        record_event(
            case_id=case_record.case_id,
            event_type=AuditEventType.JOB_QUEUED,
            message=f"Case analysis job enqueued with ID {job_id}",
            db=db,
            metadata={"job_id": job_id, "queue": "email_analysis"},
            flush=True,
        )
    else:
        # Critical failure requirement: DO NOT delete preserved evidence if Redis is down
        case_record.status = "queue_failed"
        case_record.queue_status = "failed"
        case_record.error_message = err_msg or "Failed to enqueue background processing job"
        record_event(
            case_id=case_record.case_id,
            event_type=AuditEventType.CASE_ANALYSIS_FAILED,
            message=f"Failed to enqueue case analysis job: {err_msg}",
            db=db,
            metadata={"error": err_msg},
            flush=True,
        )

    db.commit()
    db.refresh(case_record)

    return case_record
