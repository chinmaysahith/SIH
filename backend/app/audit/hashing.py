"""Deterministic Canonical JSON & Cryptographic Hashing Utilities for Audit Trail."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Union


def normalize_timestamp_str(dt: Union[datetime, str]) -> str:
    """Normalizes datetime or ISO string to a deterministic ISO 8601 UTC string."""
    if isinstance(dt, str):
        try:
            parsed = datetime.fromisoformat(dt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            else:
                parsed = parsed.astimezone(timezone.utc)
            return parsed.isoformat()
        except Exception:
            return dt

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def canonical_json(data: Any) -> str:
    """Produces a deterministic, whitespace-minimized, key-sorted JSON string.

    Ensures datetimes are normalized to explicit ISO 8601 UTC strings.
    """
    def _default_serializer(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return normalize_timestamp_str(obj)
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if hasattr(obj, "dict"):
            return obj.dict()
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        default=_default_serializer,
    )


def compute_sha256(data_bytes: bytes) -> str:
    """Calculates standard SHA-256 hexadecimal digest."""
    return hashlib.sha256(data_bytes).hexdigest()


def compute_fingerprint(data: Any) -> str:
    """Computes SHA-256 over canonical JSON serialization of arbitrary structured payload."""
    canonical_str = canonical_json(data)
    return compute_sha256(canonical_str.encode("utf-8"))


def compute_event_hash(
    case_id: str,
    event_sequence: int,
    event_type: str,
    event_timestamp_iso: Union[str, datetime],
    actor_type: str,
    actor_id: str | None,
    message: str,
    metadata: dict | None,
    previous_event_hash: str | None,
) -> str:
    """Computes a tamper-evident SHA-256 hash for a CaseEventRecord.

    Hashes a canonical representation containing all event attributes and previous hash.
    """
    ts_normalized = normalize_timestamp_str(event_timestamp_iso)
    event_payload = {
        "case_id": case_id,
        "event_sequence": event_sequence,
        "event_type": event_type,
        "event_timestamp": ts_normalized,
        "actor_type": actor_type,
        "actor_id": actor_id or None,
        "message": message,
        "metadata": metadata or {},
        "previous_event_hash": previous_event_hash or None,
    }
    canonical_repr = canonical_json(event_payload)
    return compute_sha256(canonical_repr.encode("utf-8"))
