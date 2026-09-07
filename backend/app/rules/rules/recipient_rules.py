from typing import Any, Dict
from app.rules.models import RuleCategory, RuleDefinition, RuleResult, RuleSeverity
from app.rules.registry import BaseRule


class UndisclosedRecipientsRule(BaseRule):
    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-RECIPIENT-001",
                name="Undisclosed Direct Recipients",
                description="Detects emails without explicit direct recipients or marked undisclosed-recipients.",
                category=RuleCategory.RECIPIENT,
                severity=RuleSeverity.LOW,
                default_score=5,
                false_positive_context=(
                    "Legitimate newsletters, marketing campaigns, and privacy-preserving Bcc group "
                    "distributions regularly use undisclosed recipients."
                ),
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        recipients = parsed_context.get("recipients") or {}
        to_list = recipients.get("to", []) or []

        matched = False
        reason = ""

        if not to_list:
            matched = True
            reason = "No direct 'To' recipients listed."
        else:
            first_to = to_list[0]
            raw_to = str(first_to.get("raw", "")).lower()
            addr_to = str(first_to.get("address", "")).lower()
            disp_to = str(first_to.get("display_name", "")).lower()
            if "undisclosed" in raw_to or "undisclosed" in addr_to or "undisclosed" in disp_to:
                matched = True
                reason = "Recipients marked as undisclosed."

        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=reason if matched else "Direct recipients specified.",
            evidence={"to_recipients_count": len(to_list), "reason": reason},
            rule_version=self.definition.version,
        )


# Aliases for flexibility
RuleRecipient001 = UndisclosedRecipientsRule

__all__ = [
    "UndisclosedRecipientsRule",
    "RuleRecipient001",
]

