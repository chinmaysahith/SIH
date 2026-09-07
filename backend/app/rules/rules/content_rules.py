from typing import Any, Dict, List
from app.rules.models import RuleCategory, RuleDefinition, RuleResult, RuleSeverity
from app.rules.registry import BaseRule

DEFAULT_URGENCY_TERMS = [
    "urgent",
    "immediately",
    "act now",
    "action required",
    "verify now",
    "account suspended",
    "account will be closed",
    "within 24 hours",
    "within 48 hours",
    "immediate action",
    "final notice",
]

DEFAULT_SENSITIVE_TERMS = [
    "password",
    "credentials",
    "verification code",
    "security code",
    "one-time password",
    "otp",
    "banking information",
    "bank account",
    "credit card",
    "debit card",
    "pin number",
    "ssn",
    "social security",
]

DEFAULT_THREAT_TERMS = [
    "account suspended",
    "account disabled",
    "account terminated",
    "legal action",
    "law enforcement",
    "security breach",
    "unauthorized access",
    "access restricted",
    "payment failed",
]


class UrgencyLanguageRule(BaseRule):
    def __init__(self, terms: List[str] | None = None):
        self.terms = terms or DEFAULT_URGENCY_TERMS
        super().__init__(
            RuleDefinition(
                rule_id="RULE-CONTENT-001",
                name="Urgency Language",
                description="Detects high-urgency or time-pressure language designed to prompt hasty user response.",
                category=RuleCategory.CONTENT,
                severity=RuleSeverity.LOW,
                default_score=10,
                false_positive_context=(
                    "Legitimate billing reminders, system maintenance notices, or genuine operational "
                    "alerts often use urgent wording."
                ),
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        text = ((parsed_context.get("body_text") or "") + " " + (parsed_context.get("subject") or "")).lower()
        matched_terms = [t for t in self.terms if t in text]
        matched = len(matched_terms) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=(
                f"Email contains urgency phrasing: {', '.join(matched_terms[:3])}."
                if matched
                else "No excessive urgency language detected."
            ),
            evidence={"matched_terms": matched_terms},
            rule_version=self.definition.version,
        )


class SensitiveInformationRequestRule(BaseRule):
    def __init__(self, terms: List[str] | None = None):
        self.terms = terms or DEFAULT_SENSITIVE_TERMS
        super().__init__(
            RuleDefinition(
                rule_id="RULE-CONTENT-002",
                name="Sensitive Information Request",
                description="Detects phrases soliciting passwords, credentials, OTPs, or financial data.",
                category=RuleCategory.CONTENT,
                severity=RuleSeverity.MEDIUM,
                default_score=20,
                false_positive_context=(
                    "Legitimate authentication setup emails, password reset workflows, or HR onboarding "
                    "materials may reference security credentials."
                ),
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        text = ((parsed_context.get("body_text") or "") + " " + (parsed_context.get("body_html") or "")).lower()
        matched_terms = [t for t in self.terms if t in text]
        matched = len(matched_terms) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=(
                f"Email content requests sensitive credentials/info: {', '.join(matched_terms[:3])}."
                if matched
                else "No sensitive information solicitation detected."
            ),
            evidence={"matched_terms": matched_terms},
            rule_version=self.definition.version,
        )


class ThreatLanguageRule(BaseRule):
    def __init__(self, terms: List[str] | None = None):
        self.terms = terms or DEFAULT_THREAT_TERMS
        super().__init__(
            RuleDefinition(
                rule_id="RULE-CONTENT-003",
                name="Threat / Consequence Language",
                description="Detects threatening consequences such as account suspension, termination, or legal action.",
                category=RuleCategory.CONTENT,
                severity=RuleSeverity.MEDIUM,
                default_score=15,
                false_positive_context=(
                    "Authentic incident response notifications, subscription billing failures, or policy "
                    "enforcement communications can include consequence language."
                ),
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        text = ((parsed_context.get("body_text") or "") + " " + (parsed_context.get("body_html") or "")).lower()
        matched_terms = [t for t in self.terms if t in text]
        matched = len(matched_terms) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=(
                f"Email contains consequence/threat phrasing: {', '.join(matched_terms[:3])}."
                if matched
                else "No coercive threat language detected."
            ),
            evidence={"matched_terms": matched_terms},
            rule_version=self.definition.version,
        )


class HtmlContentPresentRule(BaseRule):
    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-CONTENT-004",
                name="HTML Content Present",
                description="Identifies whether an HTML body part is present.",
                category=RuleCategory.CONTENT,
                severity=RuleSeverity.INFO,
                default_score=2,
                false_positive_context="Nearly all modern commercial and personal emails utilize HTML formatting.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        has_html = bool(parsed_context.get("body_html"))
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if has_html else 0,
            matched=has_html,
            message="Email contains HTML formatting." if has_html else "Email is plain-text only.",
            evidence={"has_html": has_html},
            rule_version=self.definition.version,
        )


# Aliases for flexibility
RuleContent001 = UrgencyLanguageRule
RuleContent002 = SensitiveInformationRequestRule
RuleContent003 = ThreatLanguageRule
RuleContent004 = HtmlContentPresentRule

__all__ = [
    "DEFAULT_URGENCY_TERMS",
    "DEFAULT_SENSITIVE_TERMS",
    "DEFAULT_THREAT_TERMS",
    "UrgencyLanguageRule",
    "SensitiveInformationRequestRule",
    "ThreatLanguageRule",
    "HtmlContentPresentRule",
    "RuleContent001",
    "RuleContent002",
    "RuleContent003",
    "RuleContent004",
]

