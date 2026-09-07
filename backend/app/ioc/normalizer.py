"""Deterministic normalization layer for Stage 5 — IOC Analysis Engine.

Normalizes extracted indicators into canonical lookup formats without destroying
the original forensic representation.
"""

import ipaddress
import re
from typing import Optional
from urllib.parse import urlsplit, urlunsplit


def normalize_domain(domain_str: str) -> Optional[str]:
    """Normalizes a domain name: lowercase, strips whitespace and trailing dot.

    Returns canonical domain or None if syntactically invalid.
    """
    if not domain_str:
        return None
    val = domain_str.strip().lower()
    if not val:
        return None

    # Remove trailing dot (DNS root representation)
    if val.endswith("."):
        val = val[:-1]

    # Validate syntax: no whitespace, slashes, or colons
    if re.search(r"[\s/:]", val):
        return None

    # Must contain at least one dot or be a recognized valid single label (excluding empty)
    labels = val.split(".")
    if not labels or any(len(label) == 0 for label in labels):
        return None

    # Check valid label characters (letters, digits, hyphens)
    for label in labels:
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label):
            return None

    return val


def normalize_ipv4(ip_str: str) -> Optional[str]:
    """Validates and normalizes an IPv4 address using standard library ipaddress.

    Returns canonical string or None if invalid or IPv6.
    """
    if not ip_str:
        return None
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.IPv4Address(cleaned)
        return str(addr)
    except (ValueError, ipaddress.AddressValueError):
        return None


def normalize_sha256(hash_str: str) -> Optional[str]:
    """Validates and normalizes a SHA-256 hash.

    Must be strictly 64 hexadecimal characters.
    """
    if not hash_str:
        return None
    cleaned = hash_str.strip().lower()
    if len(cleaned) != 64:
        return None
    if not re.match(r"^[0-9a-f]{64}$", cleaned):
        return None
    return cleaned


def normalize_url(url_str: str) -> Optional[str]:
    """Normalizes a URL for canonical threat intelligence lookup.

    Lowercases scheme and host, removes default ports (80/443), preserves path/query case.
    """
    if not url_str:
        return None
    cleaned = url_str.strip()
    if not cleaned:
        return None

    try:
        parts = urlsplit(cleaned)
        scheme = parts.scheme.lower()
        if not scheme:
            return None

        netloc = parts.netloc.lower()
        # Remove standard default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        # Canonicalize path: empty path becomes "/"
        path = parts.path if parts.path else "/"

        canonical = urlunsplit((scheme, netloc, path, parts.query, parts.fragment))
        return canonical
    except Exception:
        return None
