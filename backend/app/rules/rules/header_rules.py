from typing import Any, Dict
from app.rules.models import RuleCategory, RuleDefinition, RuleResult, RuleSeverity
from app.rules.registry import BaseRule


class MultipleReceivedHopsRule(BaseRule):
    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-HDR-001",
                name="Multiple Received Hops",
                description="Detects emails routed through 3 or more Received hops.",
                category=RuleCategory.HEADER,
                severity=RuleSeverity.LOW,
                default_score=5,
                false_positive_context=(
                    "Legitimate emails frequently traverse multiple internal hops, "
                    "spam filters, or relay infrastructure."
                ),
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        received = parsed_context.get("received_headers", []) or []
        count = len(received)
        matched = count >= 3
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Email contains {count} Received header hops." if matched else "Normal Received hop count.",
            evidence={"received_count": count},
            rule_version=self.definition.version,
        )


class MissingMessageIdRule(BaseRule):
    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-HDR-002",
                name="Missing Message-ID",
                description="Detects emails without a Message-ID header.",
                category=RuleCategory.HEADER,
                severity=RuleSeverity.LOW,
                default_score=10,
                false_positive_context=(
                    "Some automated notification or legacy internal systems omit Message-ID."
                ),
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        headers = parsed_context.get("headers", {}) or {}
        # Case-insensitive header check
        msg_id = None
        for k, v in headers.items():
            if k.lower() == "message-id":
                msg_id = v
                break

        matched = not bool(msg_id and str(msg_id).strip())
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message="Message-ID header is absent." if matched else "Message-ID header is present.",
            evidence={"message_id_present": not matched},
            rule_version=self.definition.version,
        )


class InconsistentSenderHeadersRule(BaseRule):
    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-HDR-003",
                name="Inconsistent Sender Headers",
                description="Checks if From domain differs from Return-Path domain when Return-Path is specified.",
                category=RuleCategory.HEADER,
                severity=RuleSeverity.LOW,
                default_score=10,
                false_positive_context=(
                    "Mailing lists, newsletter systems, and CRM marketing platforms commonly "
                    "use custom Return-Path domains for bounce handling."
                ),
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        sender = parsed_context.get("sender") or {}
        from_domain = sender.get("domain", "").lower().strip()

        headers = parsed_context.get("headers", {}) or {}
        return_path = None
        for k, v in headers.items():
            if k.lower() == "return-path":
                return_path = str(v)
                break

        rp_domain = ""
        if return_path and "@" in return_path:
            rp_domain = return_path.split("@", 1)[1].rstrip("> \r\n").lower().strip()

        matched = bool(from_domain and rp_domain and from_domain != rp_domain)
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=(
                f"From domain ({from_domain}) differs from Return-Path domain ({rp_domain})."
                if matched
                else "From and Return-Path domains are consistent or Return-Path absent."
            ),
            evidence={
                "from_domain": from_domain,
                "return_path_domain": rp_domain,
            },
            rule_version=self.definition.version,
        )


# Aliases for flexibility
RuleHdr001 = MultipleReceivedHopsRule
RuleHdr002 = MissingMessageIdRule
RuleHdr003 = InconsistentSenderHeadersRule

__all__ = [
    "MultipleReceivedHopsRule",
    "MissingMessageIdRule",
    "InconsistentSenderHeadersRule",
    "RuleHdr001",
    "RuleHdr002",
    "RuleHdr003",
]

