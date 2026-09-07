"""IOC extractor layer for Stage 5 — IOC Analysis Engine.

Extracts URLs, host domains, IPv4 addresses, attachment hashes, and sender domains
directly from ParsedEmail without re-parsing raw email bytes.
"""

from email.utils import parseaddr
from typing import List, Set, Tuple
from urllib.parse import urlsplit

from app.ioc.models import IOCIndicator, IOCType
from app.ioc.normalizer import (
    normalize_domain,
    normalize_ipv4,
    normalize_sha256,
    normalize_url,
)
from app.parser.models import ParsedEmail


def extract_iocs(parsed_email: ParsedEmail) -> List[IOCIndicator]:
    """Extracts, categorizes, and normalizes all indicators present in ParsedEmail."""
    indicators: List[IOCIndicator] = []
    seen: Set[Tuple[IOCType, str, str]] = set()

    def add_indicator(ioc_type: IOCType, original: str, normalized: str, source_context: str) -> None:
        key = (ioc_type, normalized, source_context)
        if key not in seen:
            seen.add(key)
            ioc_id = f"IOC-{len(indicators) + 1:03d}"
            indicators.append(
                IOCIndicator(
                    ioc_id=ioc_id,
                    ioc_type=ioc_type,
                    original_value=original,
                    normalized_value=normalized,
                    source_context=source_context,
                )
            )

    # 1. URLs and their constituent hosts (IP or Domain)
    for raw_url in parsed_email.urls:
        if not raw_url:
            continue
        norm_url = normalize_url(raw_url)
        if norm_url:
            add_indicator(IOCType.URL, raw_url, norm_url, "email_url")

        # Extract host from URL
        try:
            split_res = urlsplit(raw_url)
            host = split_res.hostname
            if host:
                # Check if host is IPv4
                norm_ip = normalize_ipv4(host)
                if norm_ip:
                    add_indicator(IOCType.IP, host, norm_ip, "url_ip")
                else:
                    # Not an IP; check if valid domain and not localhost
                    clean_host = host.strip().lower()
                    if clean_host not in ("localhost", "127.0.0.1", "::1"):
                        norm_dom = normalize_domain(host)
                        if norm_dom:
                            add_indicator(IOCType.DOMAIN, host, norm_dom, "url_domain")
        except Exception:
            pass

    # 2. Attachment SHA-256 Hashes
    for att in parsed_email.attachments:
        if att.sha256:
            norm_hash = normalize_sha256(att.sha256)
            if norm_hash:
                add_indicator(IOCType.SHA256, att.sha256, norm_hash, "attachment_hash")

    # 3. Sender Domain
    if parsed_email.sender and parsed_email.sender.domain:
        norm_s_dom = normalize_domain(parsed_email.sender.domain)
        if norm_s_dom:
            add_indicator(IOCType.DOMAIN, parsed_email.sender.domain, norm_s_dom, "sender_domain")

    # 4. Reply-To Domain
    reply_to = parsed_email.headers.get("Reply-To") or parsed_email.headers.get("reply-to")
    if reply_to:
        _, reply_addr = parseaddr(str(reply_to))
        if reply_addr and "@" in reply_addr:
            r_dom = reply_addr.split("@", 1)[1]
            norm_r_dom = normalize_domain(r_dom)
            if norm_r_dom:
                add_indicator(IOCType.DOMAIN, r_dom, norm_r_dom, "reply_to_domain")

    return indicators
