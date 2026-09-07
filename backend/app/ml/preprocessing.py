"""Text preprocessing and content extraction for Stage 4 — ML Engine.

Extracts visible, safe text from parsed email structures and formats into
composite representations for TF-IDF feature extraction.
"""

import re
from typing import Optional, Tuple
from bs4 import BeautifulSoup

from app.parser.models import ParsedEmail

PREPROCESSING_VERSION = "1.0.0"
MIN_CONTENT_LENGTH = 10


def extract_visible_html_text(html_content: str) -> str:
    """Safely extracts visible text from HTML content without executing scripts."""
    if not html_content or not html_content.strip():
        return ""
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        # Remove script and style elements
        for element in soup(["script", "style", "head", "title", "meta", "[document]"]):
            element.extract()
        text = soup.get_text(separator=" ")
        return text
    except Exception:
        # Fallback to regex tag stripping if parser fails
        return re.sub(r"<[^>]+>", " ", html_content)


def clean_text_whitespace(text: str) -> str:
    """Normalizes excessive whitespace and line breaks while preserving word boundaries."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()


def extract_content_for_ml(
    parsed_email: Optional[ParsedEmail] = None,
    subject: Optional[str] = None,
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
) -> Tuple[str, bool]:
    """Extracts composite text and determines if content is sufficient for ML analysis.

    Returns:
        (composite_text, is_sufficient)
    """
    if parsed_email is not None:
        subj = parsed_email.subject or ""
        b_text = parsed_email.body_text or ""
        b_html = parsed_email.body_html or ""
    else:
        subj = subject or ""
        b_text = body_text or ""
        b_html = body_html or ""

    clean_subj = clean_text_whitespace(subj)

    # Prefer plain text body if present; fallback to HTML visible text
    if b_text and b_text.strip():
        body_content = clean_text_whitespace(b_text)
    elif b_html and b_html.strip():
        body_content = clean_text_whitespace(extract_visible_html_text(b_html))
    else:
        body_content = ""

    # Check minimum content threshold
    combined_raw_len = len(clean_subj) + len(body_content)
    is_sufficient = combined_raw_len >= MIN_CONTENT_LENGTH

    composite_text = f"SUBJECT:\n{clean_subj}\n\nBODY:\n{body_content}"
    return composite_text, is_sufficient
