"""Stage 7 Correlation Engine Policy & Scoring Weights Configuration.

Centralizes all weights, thresholds, scaling constants, and analytical rules
to avoid magic numbers in the codebase.
"""

from app.config import CORRELATION_ENGINE_VERSION, CORRELATION_POLICY_VERSION

# Engine Baseline Weights (Sum = 1.0)
# Selected based on engineering evaluation of signal reliability:
# - Rules: Deterministic, explainable RFC/header/content tests (35%)
# - ML: Statistical probability from visible text/content (30%)
# - IOC: High-fidelity matched threat intelligence feeds (25%)
# - Geo: Network origin and contextual relay infrastructure (10%)
DEFAULT_ENGINE_WEIGHTS = {
    "rules": 0.35,
    "ml": 0.30,
    "ioc": 0.25,
    "geo": 0.10,
}

# Final Assessment Thresholds (0-100 scale)
THRESHOLD_BENIGN_MAX = 24.99
THRESHOLD_SUSPICIOUS_MAX = 59.99
# Score >= 60.00 -> HIGH_RISK

# Coverage Threshold for Assessment Validity
# If available engine weight coverage drops below 40%, assessment is INCONCLUSIVE
MIN_COVERAGE_FOR_ASSESSMENT = 40.0

# Overlap Factor for Double Counting Prevention
# When multiple engines observe the exact same underlying entity (IP, Domain, URL, Hash),
# duplicate subsequent contributions for that entity are discounted by this factor.
ENTITY_OVERLAP_DISCOUNT_FACTOR = 0.50

# Severe Asymmetric Overrides
# If an IOC is confirmed KNOWN_MALICIOUS with >= this confidence, minimum score is enforced
SEVERE_IOC_CONFIDENCE_THRESHOLD = 85
SEVERE_IOC_MIN_SCORE = 65.0  # Guarantees at least HIGH_RISK if trusted threat intel matches
