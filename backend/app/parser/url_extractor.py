import re
from typing import List, Optional
from bs4 import BeautifulSoup

# Regex matching HTTP and HTTPS URLs
URL_REGEX = re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)


def clean_url_trailing_punctuation(url: str) -> str:
    """Strips trailing sentence punctuation that may have been captured by regex."""
    while url and url[-1] in {".", ",", ";", ":", ")", "]", ">", "'", '"'}:
        url = url[:-1]
    return url


def extract_urls(body_text: Optional[str] = None, body_html: Optional[str] = None) -> List[str]:
    """Extracts and deduplicates URLs from plain-text and HTML bodies.

    Does not visit, validate, or perform destructive normalization.
    """
    seen = set()
    extracted_urls: List[str] = []

    def add_url(raw_url: str):
        if not raw_url or not isinstance(raw_url, str):
            return
        cleaned = clean_url_trailing_punctuation(raw_url.strip())
        if cleaned.lower().startswith(("http://", "https://")):
            if cleaned not in seen:
                seen.add(cleaned)
                extracted_urls.append(cleaned)

    # 1. Extract from plain-text body
    if body_text:
        for match in URL_REGEX.finditer(body_text):
            add_url(match.group(0))

    # 2. Extract from HTML body
    if body_html:
        try:
            soup = BeautifulSoup(body_html, "html.parser")

            # Extract from <a href="...">
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if isinstance(href, list):
                    href = href[0] if href else ""
                add_url(str(href))

            # Extract unlinked plaintext URLs within HTML text
            text_content = soup.get_text()
            for match in URL_REGEX.finditer(text_content):
                add_url(match.group(0))

        except Exception:
            # Fallback to direct regex on HTML if BeautifulSoup parsing fails
            for match in URL_REGEX.finditer(body_html):
                add_url(match.group(0))

    return extracted_urls
