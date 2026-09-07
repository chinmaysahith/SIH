import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from fastapi import HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.config import (
    ALLOWED_EXTENSIONS,
    MAX_UPLOAD_SIZE_BYTES,
    MAX_UPLOAD_SIZE_MB,
    QUARANTINE_DIR,
)
from app.db.models import Case

logger = logging.getLogger("email_forensics.quarantine")


def generate_case_id() -> str:
    """Generate a collision-resistant, human-readable, filesystem-safe case ID.

    Format: CASE-YYYYMMDD-<6 hex chars>
    Example: CASE-20260905-8F3A21
    """
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_hex = secrets.token_hex(3).upper()
    return f"CASE-{date_str}-{random_hex}"


def extract_and_validate_extension(filename: str | None) -> str:
    """Extract and validate the file extension against allowed extensions.

    Rejects files with unsupported extensions or missing filenames.
    """
    if not filename or not filename.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required",
        )

    # Use pure filename component to prevent path traversal in extension parsing
    pure_filename = Path(filename).name
    ext = Path(pure_filename).suffix.lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{ext}'. Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    return ext


def calculate_file_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    """Calculate the SHA-256 hash of a file on disk by reading in chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


async def process_and_quarantine_file(
    file: UploadFile,
    db: Session,
) -> Case:
    """Process uploaded email, preserve raw bytes in quarantine, verify SHA-256,

    and register the case in the database.
    """
    # 1. Validate file extension
    ext = extract_and_validate_extension(file.filename)

    # 2. Generate unique case ID
    case_id = generate_case_id()

    # 3. Construct server-controlled quarantine destination path
    # Safe storage filename: <case_id><ext>
    storage_filename = f"{case_id}{ext}"
    destination_path = QUARANTINE_DIR / storage_filename

    # Defensive path containment check
    if destination_path.resolve().parent != QUARANTINE_DIR:
        logger.error(
            "Path traversal attempt detected during quarantine path construction: %s",
            file.filename,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid storage path resolution",
        )

    # 4. Stream uploaded bytes directly to quarantine file and compute SHA-256
    upload_hasher = hashlib.sha256()
    bytes_written = 0
    chunk_size = 65536  # 64 KB chunks

    try:
        with open(destination_path, "wb") as dest:
            while chunk := await file.read(chunk_size):
                bytes_written += len(chunk)

                if bytes_written > MAX_UPLOAD_SIZE_BYTES:
                    dest.close()
                    if destination_path.exists():
                        destination_path.unlink()
                    logger.warning(
                        "Upload rejected: File size %d bytes exceeded limit %d MB",
                        bytes_written,
                        MAX_UPLOAD_SIZE_MB,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail=f"File exceeds maximum upload size of {MAX_UPLOAD_SIZE_MB}MB",
                    )

                upload_hasher.update(chunk)
                dest.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        if destination_path.exists():
            destination_path.unlink()
        logger.exception("Filesystem error while writing quarantine file")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to write evidence to quarantine storage",
        ) from exc

    # 5. Validate file is not empty
    if bytes_written == 0:
        if destination_path.exists():
            destination_path.unlink()
        logger.warning("Upload rejected: Empty file received (%s)", file.filename)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes)",
        )

    upload_sha256 = upload_hasher.hexdigest()

    # 6. Verify stored file hash (Forensic Double-Check)
    try:
        stored_file_sha256 = calculate_file_sha256(destination_path)
    except Exception as exc:
        if destination_path.exists():
            destination_path.unlink()
        logger.exception("Failed to re-read quarantined file for hash verification")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify quarantine file integrity",
        ) from exc

    if stored_file_sha256 != upload_sha256:
        if destination_path.exists():
            destination_path.unlink()
        logger.critical(
            "STORAGE INTEGRITY FAILURE: Quarantined file hash (%s) does not match upload hash (%s)",
            stored_file_sha256,
            upload_sha256,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Storage integrity failure: hash mismatch after writing",
        )

    # 7. Create database case record
    safe_original_name = Path(file.filename or "unknown").name
    case_record = Case(
        case_id=case_id,
        original_filename=safe_original_name,
        stored_path=str(destination_path.resolve()),
        sha256=upload_sha256,
        file_size=bytes_written,
        file_extension=ext,
        status="uploaded",
        upload_timestamp=datetime.now(timezone.utc),
    )

    try:
        db.add(case_record)
        db.flush()

        # Stage 8: Record initial tamper-evident audit events
        from app.audit import record_event, AuditEventType
        record_event(
            case_id=case_id,
            event_type=AuditEventType.CASE_CREATED,
            message=f"Forensic case record registered for file '{safe_original_name}'",
            db=db,
            metadata={"original_filename": safe_original_name, "file_extension": ext, "file_size": bytes_written},
            flush=True,
        )
        record_event(
            case_id=case_id,
            event_type=AuditEventType.EVIDENCE_STORED,
            message=f"Raw evidence quarantined byte-for-byte with SHA-256 {upload_sha256}",
            db=db,
            metadata={"sha256": upload_sha256, "stored_path": str(destination_path.resolve()), "file_size": bytes_written},
            flush=True,
        )

        db.commit()
        db.refresh(case_record)
    except Exception as exc:
        db.rollback()
        # Clean up the orphaned quarantine file to maintain integrity between db and store
        if destination_path.exists():
            destination_path.unlink()
        logger.exception("Failed to insert case record into SQLite database")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register case in database",
        ) from exc

    # 8. Safe metadata logging (NO raw email contents logged)
    logger.info(
        "Case registered successfully: case_id=%s, original_filename=%s, size=%d bytes, sha256=%s, status=%s",
        case_record.case_id,
        case_record.original_filename,
        case_record.file_size,
        case_record.sha256,
        case_record.status,
    )

    return case_record
