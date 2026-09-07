"""Rules Engine core evaluator.

Orchestrates rule registry instantiation, execution against parsed data,
score calculation with category caps, and summary report generation.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Union

from app.rules.models import (
    RuleResult,
    RulesEvaluationSummary,
)
from app.rules.registry import RuleRegistry, rule_registry
from app.rules.rules.attachment_rules import (
    RuleAttach001,
    RuleAttach002,
    RuleAttach003,
    RuleAttach004,
)
from app.rules.rules.content_rules import (
    RuleContent001,
    RuleContent002,
    RuleContent003,
    RuleContent004,
)
from app.rules.rules.header_rules import (
    RuleHdr001,
    RuleHdr002,
    RuleHdr003,
)
from app.rules.rules.recipient_rules import (
    RuleRecipient001,
)
from app.rules.rules.sender_rules import (
    RuleSender001,
    RuleSender002,
    RuleSender003,
)
from app.rules.rules.url_rules import (
    RuleUrl001,
    RuleUrl002,
    RuleUrl003,
    RuleUrl004,
    RuleUrl005,
)
from app.rules.scoring import calculate_scores_and_verdict

RULES_ENGINE_VERSION = "1.0.0"


def register_standard_rules(registry: RuleRegistry) -> None:
    """Register all 18 standard Stage 3 rules into the given registry."""
    # Headers (3 rules)
    registry.register(RuleHdr001())
    registry.register(RuleHdr002())
    registry.register(RuleHdr003())

    # Sender (3 rules)
    registry.register(RuleSender001())
    registry.register(RuleSender002())
    registry.register(RuleSender003())

    # Recipient (1 rule)
    registry.register(RuleRecipient001())

    # Content (4 rules)
    registry.register(RuleContent001())
    registry.register(RuleContent002())
    registry.register(RuleContent003())
    registry.register(RuleContent004())

    # URLs (5 rules)
    registry.register(RuleUrl001())
    registry.register(RuleUrl002())
    registry.register(RuleUrl003())
    registry.register(RuleUrl004())
    registry.register(RuleUrl005())

    # Attachments (4 rules)
    registry.register(RuleAttach001())
    registry.register(RuleAttach002())
    registry.register(RuleAttach003())
    registry.register(RuleAttach004())


# Initialize default singleton registry
register_standard_rules(rule_registry)


def evaluate_rules(parsed_data: Union[Dict[str, Any], Any], registry: RuleRegistry = None) -> RulesEvaluationSummary:
    """Evaluate all registered rules against a parsed email record.

    Args:
        parsed_data: ParsedData pydantic model, dictionary, or ORM ParsedDataRecord
        registry: Optional custom RuleRegistry instance. Defaults to global rule_registry.

    Returns:
        RulesEvaluationSummary containing complete breakdown, category scores, and verdict.
    """
    if registry is None:
        registry = rule_registry

    # Convert pydantic model or ORM object to standard dictionary
    data_dict: Dict[str, Any] = {}
    if hasattr(parsed_data, "model_dump"):
        data_dict = parsed_data.model_dump()
    elif hasattr(parsed_data, "dict"):
        data_dict = parsed_data.dict()
    elif isinstance(parsed_data, dict):
        data_dict = parsed_data
    else:
        # Fallback for ORM model attributes
        for attr in [
            "headers", "subject", "sender_raw", "from_header", "to_headers",
            "cc_headers", "bcc_headers", "reply_to", "return_path",
            "body_plain", "body_html", "urls", "attachments", "received_chain"
        ]:
            if hasattr(parsed_data, attr):
                data_dict[attr] = getattr(parsed_data, attr)

    # Execute all enabled rules
    all_results: list[RuleResult] = []
    active_rules = registry.get_enabled()

    for rule in active_rules:
        try:
            res = rule.evaluate(data_dict)
            all_results.append(res)
        except Exception as e:
            # Defensive execution: rule evaluation failure must not crash engine
            res = RuleResult(
                rule_id=rule.definition.rule_id,
                name=rule.definition.name,
                category=rule.definition.category,
                severity=rule.definition.severity,
                base_score=rule.definition.base_score,
                matched=False,
                score_contributed=0,
                evidence={"error": str(e)},
                rationale=rule.definition.rationale,
                remediation=rule.definition.remediation,
                false_positive_context=rule.definition.false_positive_context,
            )
            all_results.append(res)

    # Compute category-capped scores and deterministic verdict
    total_score, category_scores, verdict = calculate_scores_and_verdict(all_results)

    matched_results = [r for r in all_results if r.matched]

    return RulesEvaluationSummary(
        rules_engine_version=RULES_ENGINE_VERSION,
        evaluated_timestamp=datetime.now(timezone.utc).isoformat(),
        total_rules_evaluated=len(all_results),
        matched_rules_count=len(matched_results),
        total_score=total_score,
        verdict=verdict,
        category_scores=category_scores,
        results=all_results,
    )
