"""Streaming extractors for raw real-world datasets.

Safely handles Unix mbox files, compressed bz2 archives, and 1.4GB Enron CSV without memory exhaustion.
"""

import csv
import email
from email import policy
import hashlib
import mailbox
from pathlib import Path
import tarfile
from typing import Generator, List, Optional

from app.ml.dataset_pipeline.models import EmailSample
from app.ml.preprocessing import (
    clean_text_whitespace,
    extract_content_for_ml,
    extract_visible_html_text,
)


def compute_content_hash(subject: str, body_text: str, body_html: str) -> str:
    """Calculates deterministic content fingerprint over normalized subject and body."""
    clean_sub = clean_text_whitespace(subject).lower()
    clean_b_text = clean_text_whitespace(body_text)
    if not clean_b_text and body_html:
        clean_b_text = clean_text_whitespace(extract_visible_html_text(body_html))
    return hashlib.sha256((clean_sub + " " + clean_b_text).encode("utf-8")).hexdigest()


def extract_nazario_mbox(
    mbox_path: Path,
    dataset_name: str,
    target_label: int = 1,
) -> Generator[EmailSample, None, None]:
    """Extracts email samples from a Nazario Unix mbox archive."""
    mbox = mailbox.mbox(str(mbox_path))
    for idx, msg in enumerate(mbox):
        sub = str(msg.get("subject", "") or "")
        # Skip folder internal metadata markers
        if "DON'T DELETE THIS MESSAGE" in sub:
            continue

        body_text = ""
        body_html = ""

        try:
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    try:
                        pl = part.get_payload(decode=True)
                        if pl:
                            dec = pl.decode("utf-8", errors="replace")
                            if ct == "text/plain":
                                body_text += " " + dec
                            elif ct == "text/html":
                                body_html += " " + dec
                    except Exception:
                        pass
            else:
                ct = msg.get_content_type()
                try:
                    pl = msg.get_payload(decode=True)
                    if pl:
                        dec = pl.decode("utf-8", errors="replace")
                        if ct == "text/plain":
                            body_text = dec
                        elif ct == "text/html":
                            body_html = dec
                except Exception:
                    pass
        except Exception:
            pass

        composite, is_sufficient = extract_content_for_ml(
            subject=sub,
            body_text=body_text,
            body_html=body_html,
        )
        if not is_sufficient:
            continue

        c_hash = compute_content_hash(sub, body_text, body_html)
        yield EmailSample(
            source_dataset=dataset_name,
            source_id=f"{mbox_path.name}_{idx}",
            subject=sub,
            body_text=body_text,
            body_html=body_html,
            label=target_label,
            content_hash=c_hash,
        )


def extract_enron_csv_sampled(
    csv_path: Path,
    target_count: int = 1200,
    max_per_mailbox: int = 15,
) -> List[EmailSample]:
    """Streams the 1.4GB Enron CSV with chunked reads and extracts a balanced stratified sample."""
    csv.field_size_limit(2147483647)
    samples: List[EmailSample] = []
    seen_hashes = set()
    mailbox_counts = {}

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)  # ['file', 'message']
        row_idx = 0
        for row in reader:
            row_idx += 1
            if len(row) < 2:
                continue

            file_id = row[0]
            raw_msg = row[1]
            mailbox_id = file_id.split("/")[0] if "/" in file_id else "unknown"

            if mailbox_counts.get(mailbox_id, 0) >= max_per_mailbox:
                continue

            try:
                msg = email.message_from_string(raw_msg, policy=policy.default)
                sub = str(msg.get("subject", "") or "")
                body_text = ""
                try:
                    b_part = msg.get_body(preferencelist=("plain",))
                    if b_part:
                        body_text = str(b_part.get_content())
                except Exception:
                    pass
                if not body_text:
                    body_text = raw_msg.split("\n\n", 1)[1] if "\n\n" in raw_msg else ""
            except Exception:
                continue

            composite, is_sufficient = extract_content_for_ml(
                subject=sub,
                body_text=body_text,
                body_html="",
            )
            if not is_sufficient:
                continue

            c_hash = compute_content_hash(sub, body_text, "")
            if c_hash in seen_hashes:
                continue

            seen_hashes.add(c_hash)
            mailbox_counts[mailbox_id] = mailbox_counts.get(mailbox_id, 0) + 1
            samples.append(
                EmailSample(
                    source_dataset="enron",
                    source_id=file_id,
                    subject=sub,
                    body_text=body_text,
                    body_html="",
                    label=0,
                    content_hash=c_hash,
                )
            )

            if len(samples) >= target_count:
                break

    return samples


def extract_spamassassin_archive(
    tar_path: Path,
    dataset_name: str,
    target_label: int,
) -> Generator[EmailSample, None, None]:
    """Extracts email samples from a SpamAssassin .tar.bz2 archive."""
    with tarfile.open(str(tar_path), "r:bz2") as tar:
        for m in tar.getmembers():
            if not m.isfile():
                continue
            f = tar.extractfile(m)
            if not f:
                continue
            raw = f.read()

            try:
                msg = email.message_from_bytes(raw, policy=policy.default)
                sub = str(msg.get("subject", "") or "")
                body_text = ""
                body_html = ""

                if msg.is_multipart():
                    for part in msg.walk():
                        ct = part.get_content_type()
                        try:
                            content = str(part.get_content())
                            if ct == "text/plain":
                                body_text += " " + content
                            elif ct == "text/html":
                                body_html += " " + content
                        except Exception:
                            pl = part.get_payload(decode=True)
                            if pl:
                                dec = pl.decode("utf-8", errors="replace")
                                if ct == "text/plain":
                                    body_text += " " + dec
                                elif ct == "text/html":
                                    body_html += " " + dec
                else:
                    ct = msg.get_content_type()
                    try:
                        content = str(msg.get_content())
                        if ct == "text/plain":
                            body_text = content
                        elif ct == "text/html":
                            body_html = content
                    except Exception:
                        pl = msg.get_payload(decode=True)
                        if pl:
                            dec = pl.decode("utf-8", errors="replace")
                            if ct == "text/plain":
                                body_text = dec
                            elif ct == "text/html":
                                body_html = dec
            except Exception:
                continue

            composite, is_sufficient = extract_content_for_ml(
                subject=sub,
                body_text=body_text,
                body_html=body_html,
            )
            if not is_sufficient:
                continue

            c_hash = compute_content_hash(sub, body_text, body_html)
            yield EmailSample(
                source_dataset=dataset_name,
                source_id=f"{tar_path.name}_{m.name}",
                subject=sub,
                body_text=body_text,
                body_html=body_html,
                label=target_label,
                content_hash=c_hash,
            )
