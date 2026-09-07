"""URL inspection rules for Email Fraud Detection.

Deterministic inspection of extracted URLs:
- RULE-URL-001: URL present in email body
- RULE-URL-002: Insecure HTTP link present
- RULE-URL-003: IP-address host link
- RULE-URL-004: Suspicious URL obfuscation (@ or excessive percent-encoding)
- RULE-URL-005: Credential/auth path keyword in URL
"""

import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from app.rules.models import RuleCategory, RuleDefinition, RuleResult, RuleSeverity
from app.rules.registry import BaseRule


class UrlPresentRule(BaseRule):
    """RULE-URL-001: URL Present in Email Body."""

    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-URL-001",
                name="URL Present in Email Body",
                category=RuleCategory.URL,
                severity=RuleSeverity.INFO,
                default_score=2,
                description="Fires when one or more URLs are extracted from the email body.",
                false_positive_context="Standard newsletters, legitimate transactional receipts, and everyday correspondence regularly contain URLs.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        urls = parsed_context.get("urls") or []
        matched = len(urls) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Detected {len(urls)} URLs in email body." if matched else "No URLs found in email body.",
            evidence={
                "url_count": len(urls),
                "sample_urls": [u if isinstance(u, str) else u.get("url") for u in urls[:5]],
            },
            rule_version=self.definition.version,
        )


class InsecureHttpLinkRule(BaseRule):
    """RULE-URL-002: Insecure HTTP Link Present."""

    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-URL-002",
                name="Insecure HTTP Link Present",
                category=RuleCategory.URL,
                severity=RuleSeverity.LOW,
                default_score=10,
                description="Fires when an insecure plain-text HTTP (non-HTTPS) URL is found in the email body.",
                false_positive_context="Legacy intranet links, older tracking pixels, or non-sensitive informational websites may still use HTTP.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        urls = parsed_context.get("urls") or []
        http_urls = []
        for u in urls:
            url_str = u if isinstance(u, str) else (u.get("url", "") if isinstance(u, dict) else str(u))
            if url_str.lower().startswith("http://"):
                http_urls.append(url_str)

        matched = len(http_urls) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Found {len(http_urls)} plain-text HTTP links." if matched else "No insecure HTTP links detected.",
            evidence={
                "insecure_url_count": len(http_urls),
                "sample_insecure_urls": http_urls[:5],
            },
            rule_version=self.definition.version,
        )


class IpAddressHostLinkRule(BaseRule):
    """RULE-URL-003: IP-Address Host Link."""

    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-URL-003",
                name="IP-Address Host Link",
                category=RuleCategory.URL,
                severity=RuleSeverity.HIGH,
                default_score=25,
                description="Fires when a URL's host is a raw IPv4 or IPv6 address rather than a registered domain name.",
                false_positive_context="Internal corporate intranet links referencing private RFC 1918 addresses or developer test environments.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        urls = parsed_context.get("urls") or []
        ip_urls = []

        for u in urls:
            url_str = u if isinstance(u, str) else (u.get("url", "") if isinstance(u, dict) else str(u))
            try:
                parsed = urlparse(url_str)
                hostname = parsed.hostname
                if hostname:
                    clean_host = hostname.strip("[]")
                    ipaddress.ip_address(clean_host)
                    ip_urls.append(url_str)
            except (ValueError, AttributeError):
                continue

        matched = len(ip_urls) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Found {len(ip_urls)} URLs hosted on raw IP addresses." if matched else "No IP address host links detected.",
            evidence={
                "ip_host_url_count": len(ip_urls),
                "sample_ip_urls": ip_urls[:5],
            },
            rule_version=self.definition.version,
        )


class SuspiciousUrlObfuscationRule(BaseRule):
    """RULE-URL-004: Suspicious URL Obfuscation."""

    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-URL-004",
                name="Suspicious URL Obfuscation",
                category=RuleCategory.URL,
                severity=RuleSeverity.MEDIUM,
                default_score=20,
                description="Fires when a URL employs obfuscation techniques such as userinfo '@' symbol or excessive percent-encoding (>3 '%').",
                false_positive_context="Legitimate redirectors, SSO federation links, or complex marketing campaign tracker query parameters.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        urls = parsed_context.get("urls") or []
        obfuscated_urls = []

        for u in urls:
            url_str = u if isinstance(u, str) else (u.get("url", "") if isinstance(u, dict) else str(u))
            if not url_str:
                continue

            has_at_userinfo = False
            excessive_encoding = False

            try:
                parsed = urlparse(url_str)
                if parsed.username or "@" in (parsed.netloc or ""):
                    has_at_userinfo = True
            except Exception:
                pass

            if url_str.count("%") > 3:
                excessive_encoding = True

            if has_at_userinfo or excessive_encoding:
                obfuscated_urls.append({
                    "url": url_str,
                    "has_at_userinfo": has_at_userinfo,
                    "excessive_encoding": excessive_encoding,
                    "percent_count": url_str.count("%"),
                })

        matched = len(obfuscated_urls) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Found {len(obfuscated_urls)} obfuscated URLs." if matched else "No obfuscated URLs detected.",
            evidence={
                "obfuscated_url_count": len(obfuscated_urls),
                "obfuscated_samples": obfuscated_urls[:5],
            },
            rule_version=self.definition.version,
        )


class CredentialAuthPathRule(BaseRule):
    """RULE-URL-005: Credential / Auth Path Keyword in URL."""

    AUTH_KEYWORDS = ("login", "signin", "verify", "password", "account", "secure", "update")

    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-URL-005",
                name="Credential / Auth Path Keyword in URL",
                category=RuleCategory.URL,
                severity=RuleSeverity.MEDIUM,
                default_score=15,
                description="Fires when a URL path or query string contains authentication or credential keywords.",
                false_positive_context="Legitimate password reset emails, corporate portal links, or account management notifications.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        urls = parsed_context.get("urls") or []
        matched_urls = []

        for u in urls:
            url_str = u if isinstance(u, str) else (u.get("url", "") if isinstance(u, dict) else str(u))
            try:
                parsed = urlparse(url_str)
                path_and_query = f"{parsed.path} {parsed.query}".lower()
                found_keywords = [kw for kw in self.AUTH_KEYWORDS if re.search(r"\b" + re.escape(kw) + r"\b", path_and_query)]
                if found_keywords:
                    matched_urls.append({
                        "url": url_str,
                        "matched_keywords": found_keywords,
                    })
            except Exception:
                continue

        matched = len(matched_urls) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Found {len(matched_urls)} URLs with authentication paths." if matched else "No credential keywords in URL paths.",
            evidence={
                "credential_url_count": len(matched_urls),
                "matched_samples": matched_urls[:5],
            },
            rule_version=self.definition.version,
        )


# Aliases for flexibility
RuleUrl001 = UrlPresentRule
RuleUrl002 = InsecureHttpLinkRule
RuleUrl003 = IpAddressHostLinkRule
RuleUrl004 = SuspiciousUrlObfuscationRule
RuleUrl005 = CredentialAuthPathRule

__all__ = [
    "UrlPresentRule",
    "InsecureHttpLinkRule",
    "IpAddressHostLinkRule",
    "SuspiciousUrlObfuscationRule",
    "CredentialAuthPathRule",
    "RuleUrl001",
    "RuleUrl002",
    "RuleUrl003",
    "RuleUrl004",
    "RuleUrl005",
]

