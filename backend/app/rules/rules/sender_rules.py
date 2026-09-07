from typing import Any, Dict, List
from app.rules.models import RuleCategory, RuleDefinition, RuleResult, RuleSeverity
from app.rules.registry import BaseRule

# Configurable brands and high-trust identities commonly impersonated
HIGH_TRUST_BRANDS = [
    "microsoft",
    "apple",
    "google",
    "paypal",
    "amazon",
    "netflix",
    "bank of america",
    "chase",
    "wells fargo",
    "it support",
    "helpdesk",
    "security team",
    "account security",
    "executive office",
]


class ReplyToMismatchRule(BaseRule):
    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-SENDER-001",
                name="Reply-To Domain Mismatch",
                description="Detects when the Reply-To domain differs from the From domain.",
                category=RuleCategory.SENDER,
                severity=RuleSeverity.MEDIUM,
                default_score=20,
                false_positive_context=(
                    "Legitimate organizations may use external customer support systems, "
                    "ticketing systems (e.g. Zendesk), or marketing platforms for replies."
                ),
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        sender = parsed_context.get("sender") or {}
        from_domain = sender.get("domain", "").lower().strip()

        recipients = parsed_context.get("recipients") or {}
        reply_to_list = recipients.get("reply_to", []) or []

        matched = False
        reply_to_domain = ""

        if from_domain and reply_to_list:
            first_reply = reply_to_list[0]
            reply_to_domain = first_reply.get("domain", "").lower().strip()
            if reply_to_domain and reply_to_domain != from_domain:
                matched = True

        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=(
                f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})."
                if matched
                else "Reply-To domain matches From domain or is not specified."
            ),
            evidence={
                "from_domain": from_domain,
                "reply_to_domain": reply_to_domain,
            },
            rule_version=self.definition.version,
        )


class DisplayNameImpersonationRule(BaseRule):
    def __init__(self, brands: List[str] | None = None):
        self.brands = brands or HIGH_TRUST_BRANDS
        super().__init__(
            RuleDefinition(
                rule_id="RULE-SENDER-002",
                name="Display Name Impersonation Heuristic",
                description="Detects high-trust brand or role in display name with an unrelated sender domain.",
                category=RuleCategory.SENDER,
                severity=RuleSeverity.HIGH,
                default_score=25,
                false_positive_context=(
                    "Legitimate external contractors, multi-brand partners, or authorized resellers "
                    "may reference client brand names."
                ),
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        sender = parsed_context.get("sender") or {}
        display_name = sender.get("display_name", "").lower()
        from_domain = sender.get("domain", "").lower()

        matched_brand = None
        if display_name and from_domain:
            for brand in self.brands:
                if brand in display_name:
                    # Clean brand name for domain token comparison
                    brand_token = brand.replace(" ", "")
                    # If the sender domain does NOT contain the brand token, it's an indicator
                    if brand_token not in from_domain:
                        matched_brand = brand
                        break

        matched = matched_brand is not None
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=(
                f"Display name references '{matched_brand}' while sender domain is '{from_domain}'."
                if matched
                else "Display name is consistent or does not claim recognized high-trust identity."
            ),
            evidence={
                "display_name": sender.get("display_name", ""),
                "from_domain": from_domain,
                "claimed_brand": matched_brand,
            },
            rule_version=self.definition.version,
        )


class MissingSenderDomainRule(BaseRule):
    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-SENDER-003",
                name="Missing Sender Domain",
                description="Detects emails where From address has no domain or is unparseable.",
                category=RuleCategory.SENDER,
                severity=RuleSeverity.LOW,
                default_score=15,
                false_positive_context="Internal mail systems or local daemon notifications may omit FQDN domains.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        sender = parsed_context.get("sender") or {}
        domain = sender.get("domain", "").strip()
        matched = not bool(domain)
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message="Sender domain is missing or invalid." if matched else f"Sender domain is present: {domain}.",
            evidence={"sender_domain": domain},
            rule_version=self.definition.version,
        )


# Aliases for flexibility
RuleSender001 = ReplyToMismatchRule
RuleSender002 = DisplayNameImpersonationRule
RuleSender003 = MissingSenderDomainRule

__all__ = [
    "HIGH_TRUST_BRANDS",
    "ReplyToMismatchRule",
    "DisplayNameImpersonationRule",
    "MissingSenderDomainRule",
    "RuleSender001",
    "RuleSender002",
    "RuleSender003",
]

