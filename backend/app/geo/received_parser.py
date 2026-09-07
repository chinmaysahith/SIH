import re
from typing import List, Optional
from app.geo.models import CandidateIP, IPClassification
from app.geo.ip_classifier import classify_ip

# Regex patterns to spot candidate IPv4 and IPv6 addresses inside headers
IPV4_CANDIDATE_REGEX = re.compile(
    r"(?<![0-9a-zA-Z\.])(\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)(?![0-9a-zA-Z\.])"
)
IPV6_CANDIDATE_REGEX = re.compile(
    r"(?<![0-9a-zA-Z:])((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:)(?::[0-9a-fA-F]{1,4}){1,6})(?![0-9a-zA-Z:])"
)


def parse_received_headers(received_headers: List[str]) -> List[CandidateIP]:
    """Parses Received headers and extracts candidate IPs with hop indices and context.

    Note on ordering:
    In standard RFC 5322 emails, each transit MTA prepends its 'Received:' header.
    Therefore, received_headers[0] is typically the recipient's final hop (most recent),
    and received_headers[-1] is typically the origin hop (earliest).
    To analyze the chronological path from client to recipient:
    - Hop index 0 is assigned to the earliest hop (received_headers[-1]),
    - Higher indices correspond to later downstream hops towards the recipient.
    """
    if not received_headers:
        return []

    # Reverse list so hop_index 0 = earliest originating hop
    chronological_headers = list(reversed(received_headers))
    candidates: List[CandidateIP] = []
    seen_ips = set()

    for hop_idx, header_raw in enumerate(chronological_headers):
        header_text = header_raw.strip()
        found_in_hop = []

        # Find reverse DNS / hostname hint if present (e.g., "from mail.example.com (mail.example.com [1.2.3.4])")
        rdns_hint = None
        from_match = re.search(r"from\s+([a-zA-Z0-9\.\-_]+)", header_text, re.IGNORECASE)
        if from_match:
            candidate_rdns = from_match.group(1).strip("[]()")
            if "." in candidate_rdns and not candidate_rdns.replace(".", "").isdigit():
                rdns_hint = candidate_rdns

        # Find IPv4 candidates
        for match in IPV4_CANDIDATE_REGEX.finditer(header_text):
            ip_str = match.group(1)
            found_in_hop.append(ip_str)

        # Find IPv6 candidates
        for match in IPV6_CANDIDATE_REGEX.finditer(header_text):
            ip_str = match.group(1)
            found_in_hop.append(ip_str)

        # Process each IP found in this hop
        for ip_str in found_in_hop:
            classification, version = classify_ip(ip_str)
            if classification == IPClassification.INVALID:
                continue

            # Identify if candidate is suitable for origin consideration:
            # Must be GLOBAL or DOCUMENTATION (for RFC test fixtures)
            is_origin = classification in (IPClassification.GLOBAL, IPClassification.DOCUMENTATION)

            # Store candidate observation
            candidates.append(
                CandidateIP(
                    ip=ip_str,
                    ip_version=version,
                    classification=classification,
                    hop_index=hop_idx,
                    raw_header_snippet=header_text[:120],
                    reverse_dns_hint=rdns_hint,
                    is_origin_candidate=is_origin,
                )
            )

    return candidates
