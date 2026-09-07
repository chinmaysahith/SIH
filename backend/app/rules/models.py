from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field



class RuleSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleCategory(str, Enum):
    HEADER = "header"
    SENDER = "sender"
    RECIPIENT = "recipient"
    CONTENT = "content"
    URL = "url"
    ATTACHMENT = "attachment"


class RulesVerdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"


class RuleDefinition(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    rule_id: str
    name: str
    description: str = ""
    category: RuleCategory
    severity: RuleSeverity
    default_score: int = Field(default=0, alias="base_score")
    rationale: str = ""
    remediation: str = ""
    enabled: bool = True
    version: str = "1.0.0"
    false_positive_context: str = ""

    @property
    def base_score(self) -> int:
        return self.default_score


class RuleResult(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    rule_id: str
    rule_name: str = Field(default="", alias="name")
    category: RuleCategory
    severity: RuleSeverity
    score: int = Field(default=0, alias="score_contributed")
    matched: bool
    message: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)
    rule_version: str = "1.0.0"
    rationale: str = ""
    remediation: str = ""
    false_positive_context: str = ""

    @property
    def score_contributed(self) -> int:
        return self.score

    @property
    def name(self) -> str:
        return self.rule_name


class RulesEvaluationSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    case_id: Optional[str] = None
    rules_engine_version: str
    evaluated_timestamp: Union[datetime, str]
    total_score: int
    rules_verdict: RulesVerdict = Field(alias="verdict")
    matched_rules_count: int
    total_rules_evaluated: int
    category_scores: Dict[str, int]
    results: List[RuleResult]

    @property
    def verdict(self) -> RulesVerdict:
        return self.rules_verdict

