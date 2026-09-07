from typing import List, Optional, Tuple
from app.geo.models import CandidateIP, IPClassification, OriginConfidence


def select_origin_ip(
    candidates: List[CandidateIP]
) -> Tuple[Optional[str], str, OriginConfidence, List[str]]:
    """Selects the most plausible originating network IP using the earliest_plausible_public_ip heuristic.

    Heuristic Logic:
    1. Filter candidates to only those that are plausible public network origins:
       - Classification == GLOBAL or DOCUMENTATION (for RFC 5737 / RFC 3849 test environments).
       - Exclude PRIVATE, LOOPBACK, LINK_LOCAL, MULTICAST, RESERVED.
    2. Sort by hop_index ascending (hop 0 = earliest observed hop in chain).
    3. If multiple public IPs exist at the earliest hop, take the first one observed.
    4. Determine confidence:
       - HIGH: Candidate is at hop 0 or 1, and there are multiple valid hops forming a continuous chain.
       - MEDIUM: Candidate is at a later hop (> 1) because earlier hops were private/relay, or single hop present.
       - LOW: Only 1 hop total with minimal context or synthetic appearance.
       - UNKNOWN: No plausible public/candidate IP found.
    5. Generate analytical limitations detailing any caveats (e.g. internal hops bypassed, spoofing risk).

    Returns:
        (selected_ip, selection_method, confidence, limitations)
    """
    method = "earliest_plausible_public_ip"
    limitations: List[str] = []

    if not candidates:
        limitations.append("No Received headers or candidate IP addresses found in the message.")
        return None, method, OriginConfidence.UNKNOWN, limitations

    # Check for presence of private/loopback hops
    private_hops = [c for c in candidates if c.classification in (IPClassification.PRIVATE, IPClassification.LOOPBACK)]
    if private_hops:
        limitations.append(f"Ignored {len(private_hops)} private/internal RFC 1918/loopback relay hop(s).")

    # Filter to public/documentation candidates
    origin_candidates = [c for c in candidates if c.is_origin_candidate]

    if not origin_candidates:
        limitations.append(
            "All identified hops belong to private, loopback, or reserved subnets; no public originating IP detected."
        )
        return None, method, OriginConfidence.UNKNOWN, limitations

    # Sort by hop_index ascending
    origin_candidates.sort(key=lambda c: c.hop_index)
    selected = origin_candidates[0]

    # Evaluate confidence
    total_hops = max((c.hop_index for c in candidates), default=0) + 1
    if selected.hop_index == 0 and total_hops >= 2:
        confidence = OriginConfidence.HIGH
    elif selected.hop_index <= 2 and total_hops >= 2:
        confidence = OriginConfidence.MEDIUM
        limitations.append(
            f"Selected candidate is at hop index {selected.hop_index} due to earlier private/internal relays."
        )
    elif total_hops == 1:
        confidence = OriginConfidence.LOW
        limitations.append("Message contains only a single Received header hop; high susceptibility to forged headers.")
    else:
        confidence = OriginConfidence.LOW
        limitations.append("Origin candidate is located deep downstream; upstream hops may have been stripped or forged.")

    if selected.classification == IPClassification.DOCUMENTATION:
        limitations.append(
            f"Selected IP {selected.ip} is from RFC 5737/3849 documentation test range."
        )

    limitations.append(
        "Attacker may have utilized VPN, Tor, compromised proxy, or forged intermediate MTA headers."
    )

    return selected.ip, method, confidence, limitations
