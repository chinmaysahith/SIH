from typing import Dict, List, Tuple
from app.rules.models import RuleCategory, RuleResult, RulesVerdict

# Category score caps to prevent uncontrolled inflation from related indicators
CATEGORY_CAPS: Dict[str, int] = {
    RuleCategory.HEADER.value: 20,
    RuleCategory.SENDER.value: 35,
    RuleCategory.RECIPIENT.value: 10,
    RuleCategory.CONTENT.value: 35,
    RuleCategory.URL.value: 40,
    RuleCategory.ATTACHMENT.value: 45,
}

MAX_TOTAL_SCORE = 100

VERDICT_THRESHOLDS = {
    "SUSPICIOUS": 20,
    "HIGH_RISK": 50,
}


def calculate_scores_and_verdict(results: List[RuleResult]) -> Tuple[int, Dict[str, int], RulesVerdict]:
    """Aggregates matched rule scores applying category caps and determines

    the deterministic rules_verdict.

    Returns:
        (total_score: int, category_scores: Dict[str, int], verdict: RulesVerdict)
    """
    raw_category_totals: Dict[str, int] = {cat.value: 0 for cat in RuleCategory}

    for res in results:
        if res.matched and res.score > 0:
            cat_key = res.category.value if isinstance(res.category, RuleCategory) else str(res.category)
            raw_category_totals[cat_key] = raw_category_totals.get(cat_key, 0) + res.score

    # Apply category caps
    capped_category_scores: Dict[str, int] = {}
    for cat_key, raw_score in raw_category_totals.items():
        cap = CATEGORY_CAPS.get(cat_key, 100)
        capped_category_scores[cat_key] = min(raw_score, cap)

    # Calculate overall total score (bounded to MAX_TOTAL_SCORE)
    total_score = min(sum(capped_category_scores.values()), MAX_TOTAL_SCORE)

    # Determine rules verdict
    if total_score >= VERDICT_THRESHOLDS["HIGH_RISK"]:
        verdict = RulesVerdict.HIGH_RISK
    elif total_score >= VERDICT_THRESHOLDS["SUSPICIOUS"]:
        verdict = RulesVerdict.SUSPICIOUS
    else:
        verdict = RulesVerdict.BENIGN

    return total_score, capped_category_scores, verdict
