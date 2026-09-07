"""Rules Engine package for Email Fraud Detection.

Deterministic, explainable security and fraud evaluation based on parsed email artifacts.
"""

from app.rules.engine import (
    RULES_ENGINE_VERSION,
    evaluate_rules,
    register_standard_rules,
)
from app.rules.models import (
    RuleCategory,
    RuleDefinition,
    RuleResult,
    RuleSeverity,
    RulesEvaluationSummary,
    RulesVerdict,
)
from app.rules.registry import BaseRule, RuleRegistry, rule_registry

__all__ = [
    "RULES_ENGINE_VERSION",
    "evaluate_rules",
    "register_standard_rules",
    "RuleCategory",
    "RuleSeverity",
    "RulesVerdict",
    "RuleDefinition",
    "RuleResult",
    "RulesEvaluationSummary",
    "BaseRule",
    "RuleRegistry",
    "rule_registry",
]
