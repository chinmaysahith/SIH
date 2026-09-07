from abc import ABC, abstractmethod
from typing import Any, Dict, List, Type
from app.rules.models import RuleDefinition, RuleResult


class BaseRule(ABC):
    """Abstract base class for all deterministic security rules."""

    def __init__(self, definition: RuleDefinition):
        self.definition = definition

    @abstractmethod
    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        """Evaluates the rule against extracted email context."""
        pass


class RuleRegistry:
    """Registry maintaining active rules for the rules engine."""

    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}

    def register(self, rule: BaseRule):
        """Registers a rule instance."""
        self._rules[rule.definition.rule_id] = rule

    def get_all_rules(self) -> List[BaseRule]:
        """Returns all registered enabled rules."""
        return [r for r in self._rules.values() if r.definition.enabled]

    def get_enabled(self) -> List[BaseRule]:
        """Returns all registered enabled rules."""
        return [r for r in self._rules.values() if r.definition.enabled]

    def get_all(self) -> List[BaseRule]:
        """Returns all registered rules regardless of enabled status."""
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> BaseRule | None:
        """Fetches rule by rule_id."""
        return self._rules.get(rule_id)

    def clear(self):
        """Clears registered rules (useful in tests)."""
        self._rules.clear()


# Global registry instance
rule_registry = RuleRegistry()

