from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class HeaderAddress(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    raw: str = ""
    display_name: str = ""
    address: str = ""
    domain: str = ""


class AttachmentMetadata(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    filename: str
    content_type: str
    size: int
    sha256: str
    stored_path: str
    content_disposition: Optional[str] = None


class ParsedEmail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    parser_version: str
    parsed_timestamp: datetime
    headers: Dict[str, Any] = Field(default_factory=dict)
    received_headers: List[str] = Field(default_factory=list)
    sender: Optional[HeaderAddress] = None
    recipients: Dict[str, List[HeaderAddress]] = Field(default_factory=dict)
    subject: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    parser_status: str = "success"
    error_message: Optional[str] = None
