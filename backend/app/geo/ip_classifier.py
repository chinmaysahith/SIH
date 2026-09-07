import ipaddress
from typing import Tuple
from app.geo.models import IPClassification

# RFC 5737 IPv4 Documentation subnets:
# 192.0.2.0/24 (TEST-NET-1)
# 198.51.100.0/24 (TEST-NET-2)
# 203.0.113.0/24 (TEST-NET-3)
RFC5737_NETWORKS = [
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
]

# RFC 3849 IPv6 Documentation subnet:
# 2001:db8::/32
RFC3849_NETWORK = ipaddress.IPv6Network("2001:db8::/32")


def classify_ip(ip_str: str) -> Tuple[IPClassification, int]:
    """Classifies an IP address string using standard library ipaddress.

    Returns:
        (IPClassification, ip_version) where ip_version is 4, 6, or 0 if invalid.
    """
    clean_ip = ip_str.strip()
    # Strip brackets if present (e.g. [2001:db8::1] or [1.2.3.4])
    if clean_ip.startswith("[") and clean_ip.endswith("]"):
        clean_ip = clean_ip[1:-1]

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return IPClassification.INVALID, 0

    version = ip_obj.version

    # Check documentation ranges first (RFC 5737 & RFC 3849)
    if version == 4:
        for net in RFC5737_NETWORKS:
            if ip_obj in net:
                return IPClassification.DOCUMENTATION, version
    elif version == 6:
        if ip_obj in RFC3849_NETWORK:
            return IPClassification.DOCUMENTATION, version

    if ip_obj.is_loopback:
        return IPClassification.LOOPBACK, version
    if ip_obj.is_link_local:
        return IPClassification.LINK_LOCAL, version
    if ip_obj.is_private:
        return IPClassification.PRIVATE, version
    if ip_obj.is_multicast:
        return IPClassification.MULTICAST, version
    if ip_obj.is_reserved:
        return IPClassification.RESERVED, version

    if ip_obj.is_global:
        return IPClassification.GLOBAL, version

    return IPClassification.RESERVED, version
