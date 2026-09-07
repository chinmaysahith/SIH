"""Data structures for Stage 4.5 real-world ML dataset pipeline."""

from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class EmailSample:
    """Normalized internal representation for email training/validation samples."""

    source_dataset: str
    source_id: str
    subject: str
    body_text: str
    body_html: str
    label: int  # 0 = LEGITIMATE, 1 = PHISHING
    content_hash: str

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)
