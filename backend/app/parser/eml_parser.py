import email
import email.policy
from email.header import decode_header
from email.utils import getaddresses, parseaddr
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import ATTACHMENTS_DIR, PARSER_VERSION
from app.parser.models import AttachmentMetadata, HeaderAddress, ParsedEmail
from app.parser.url_extractor import extract_urls

logger = logging.getLogger("email_forensics.parser")


def decode_mime_header(val: Optional[str]) -> str:
    """Decodes RFC 2047 MIME encoded-word headers safely."""
    if not val:
        return ""
    try:
        decoded_parts = []
        for part, encoding in decode_header(val):
            if isinstance(part, bytes):
                enc = encoding or "utf-8"
                try:
                    decoded_parts.append(part.decode(enc, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    decoded_parts.append(part.decode("latin1", errors="replace"))
            else:
                decoded_parts.append(str(part))
        return "".join(decoded_parts)
    except Exception:
        return str(val)


def parse_address(raw_header: Optional[str]) -> Optional[HeaderAddress]:
    """Parses a single email address into display_name, address, and domain."""
    if not raw_header or not raw_header.strip():
        return None
    decoded = decode_mime_header(raw_header)
    display_name, addr = parseaddr(decoded)
    domain = ""
    if "@" in addr:
        domain = addr.split("@", 1)[1].lower().strip()
    return HeaderAddress(
        raw=raw_header,
        display_name=display_name.strip(),
        address=addr.strip(),
        domain=domain,
    )


def parse_address_list(raw_headers: List[str]) -> List[HeaderAddress]:
    """Parses multiple or comma-separated recipient addresses."""
    results: List[HeaderAddress] = []
    if not raw_headers:
        return results

    combined = ", ".join(raw_headers)
    decoded = decode_mime_header(combined)
    parsed_pairs = getaddresses([decoded])

    for display_name, addr in parsed_pairs:
        addr_clean = addr.strip()
        if not addr_clean:
            continue
        domain = addr_clean.split("@", 1)[1].lower().strip() if "@" in addr_clean else ""
        results.append(
            HeaderAddress(
                raw=combined,
                display_name=display_name.strip(),
                address=addr_clean,
                domain=domain,
            )
        )
    return results


def decode_body_bytes(payload: bytes, declared_charset: Optional[str]) -> str:
    """Decodes raw message bytes to string trying declared charset and fallbacks."""
    charsets_to_try = [declared_charset, "utf-8", "windows-1252", "latin1"]
    for cs in charsets_to_try:
        if cs:
            try:
                return payload.decode(cs)
            except (LookupError, UnicodeDecodeError):
                continue
    return payload.decode("utf-8", errors="replace")


def parse_email(raw_bytes: bytes, case_id: str) -> ParsedEmail:
    """Parses raw email bytes into a structured ParsedEmail object.

    The original bytes are never modified. Attachments are saved separately
    in data/attachments/<case_id>/ with server-controlled filenames.
    """
    parsed_timestamp = datetime.now(timezone.utc)
    errors: List[str] = []

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
    except Exception as exc:
        logger.exception("Failed to parse raw bytes with email.message_from_bytes")
        return ParsedEmail(
            case_id=case_id,
            parser_version=PARSER_VERSION,
            parsed_timestamp=parsed_timestamp,
            parser_status="failed",
            error_message=f"Corrupt MIME structure: {str(exc)}",
        )

    # 1. Extract Headers
    raw_headers_dict: Dict[str, Any] = {}
    received_headers: List[str] = []

    try:
        for k, v in msg.items():
            k_lower = k.lower()
            decoded_val = decode_mime_header(v)
            if k_lower == "received":
                received_headers.append(v)
            else:
                if k in raw_headers_dict:
                    if isinstance(raw_headers_dict[k], list):
                        raw_headers_dict[k].append(decoded_val)
                    else:
                        raw_headers_dict[k] = [raw_headers_dict[k], decoded_val]
                else:
                    raw_headers_dict[k] = decoded_val
    except Exception as exc:
        errors.append(f"Header extraction warning: {str(exc)}")

    # 2. Extract Sender and Recipients
    from_header = msg.get("From")
    sender = parse_address(from_header) if from_header else None

    recipients: Dict[str, List[HeaderAddress]] = {
        "to": parse_address_list(msg.get_all("To", [])),
        "cc": parse_address_list(msg.get_all("Cc", [])),
        "bcc": parse_address_list(msg.get_all("Bcc", [])),
        "reply_to": parse_address_list(msg.get_all("Reply-To", [])),
    }

    subject_raw = msg.get("Subject")
    subject = decode_mime_header(subject_raw) if subject_raw else None

    # 3. MIME Traversal: Extract Body (Plain Text & HTML) and Attachments
    body_text_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[AttachmentMetadata] = []
    attachment_counter = 1

    case_attachments_dir = ATTACHMENTS_DIR / case_id

    for part in msg.walk():
        content_type = part.get_content_type().lower()
        disposition = str(part.get("Content-Disposition", "")).lower()
        filename_raw = part.get_filename()

        # Check if part is an attachment
        is_attachment = (
            "attachment" in disposition
            or bool(filename_raw)
            or (content_type not in ["text/plain", "text/html", "multipart/mixed", "multipart/alternative", "multipart/related"])
        )

        if is_attachment and not part.is_multipart():
            try:
                payload = part.get_payload(decode=True)
                if payload is not None:
                    # Determine safe filename and extension
                    safe_orig_filename = Path(filename_raw or f"attachment_{attachment_counter}").name
                    suffix = Path(safe_orig_filename).suffix.lower() or ".bin"
                    # Server-controlled safe storage filename
                    storage_filename = f"attachment_{attachment_counter:03d}{suffix}"

                    # Ensure case attachments directory exists
                    case_attachments_dir.mkdir(parents=True, exist_ok=True)
                    stored_file_path = case_attachments_dir / storage_filename

                    # Strict path containment verification
                    if stored_file_path.resolve().parent != case_attachments_dir.resolve():
                        raise ValueError(f"Path traversal detected in attachment: {filename_raw}")

                    # Write attachment bytes safely
                    with open(stored_file_path, "wb") as f:
                        f.write(payload)

                    # Compute and verify SHA-256
                    hasher = hashlib.sha256(payload)
                    att_sha256 = hasher.hexdigest()

                    # Double-check file on disk
                    disk_hasher = hashlib.sha256()
                    with open(stored_file_path, "rb") as f:
                        while chunk := f.read(65536):
                            disk_hasher.update(chunk)
                    if disk_hasher.hexdigest() != att_sha256:
                        raise IOError(f"Attachment hash verification failed for {storage_filename}")

                    attachments.append(
                        AttachmentMetadata(
                            filename=safe_orig_filename,
                            content_type=content_type,
                            size=len(payload),
                            sha256=att_sha256,
                            stored_path=str(stored_file_path.resolve()),
                            content_disposition=disposition or None,
                        )
                    )
                    attachment_counter += 1
            except Exception as exc:
                errors.append(f"Failed to extract attachment '{filename_raw}': {str(exc)}")
                logger.exception("Attachment extraction error")
            continue

        # Extract Text and HTML bodies
        if not part.is_multipart():
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset()
                    decoded_text = decode_body_bytes(payload, charset)
                    if content_type == "text/plain":
                        body_text_parts.append(decoded_text)
                    elif content_type == "text/html":
                        body_html_parts.append(decoded_text)
            except Exception as exc:
                errors.append(f"Body decoding error ({content_type}): {str(exc)}")
                logger.warning("Body decoding error for part %s", content_type)

    final_body_text = "\n\n".join(body_text_parts) if body_text_parts else None
    final_body_html = "\n\n".join(body_html_parts) if body_html_parts else None

    # 4. Extract URLs
    urls = extract_urls(final_body_text, final_body_html)

    # 5. Determine Parser Status
    parser_status = "success"
    if errors:
        parser_status = "partial"

    logger.info(
        "PARSING COMPLETE: case_id=%s, version=%s, status=%s, headers=%d, urls=%d, attachments=%d",
        case_id,
        PARSER_VERSION,
        parser_status,
        len(raw_headers_dict),
        len(urls),
        len(attachments),
    )

    return ParsedEmail(
        case_id=case_id,
        parser_version=PARSER_VERSION,
        parsed_timestamp=parsed_timestamp,
        headers=raw_headers_dict,
        received_headers=received_headers,
        sender=sender,
        recipients=recipients,
        subject=subject,
        body_text=final_body_text,
        body_html=final_body_html,
        urls=urls,
        attachments=attachments,
        parser_status=parser_status,
        error_message="; ".join(errors) if errors else None,
    )
