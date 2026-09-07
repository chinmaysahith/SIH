"""Core Correlation Engine Implementation for Stage 7.

Coordinates signal normalization, weight renormalization, double counting resolution,
conflict detection, ranking of top evidence, explanation synthesis, and final assessment.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from app.config import (
    CORRELATION_ENGINE_VERSION,
    CORRELATION_POLICY_VERSION,
    GEO_ANALYSIS_VERSION,
    IOC_ENGINE_VERSION,
    PARSER_VERSION,
)
from app.db.models import (
    Case,
    GeoOriginResultRecord,
    IOCResultRecord,
    MLResultRecord,
    ParsedData,
    RuleResultRecord,
)
from app.correlation.models import (
    CorrelationConfidence,
    CorrelationConflict,
    CorrelationResult,
    EngineSignal,
    EvidenceCoverage,
    FinalAssessment,
    SignalAvailability,
    TopEvidenceItem,
    UpstreamVersions,
)
from app.correlation.policy import (
    DEFAULT_ENGINE_WEIGHTS,
    ENTITY_OVERLAP_DISCOUNT_FACTOR,
    MIN_COVERAGE_FOR_ASSESSMENT,
    SEVERE_IOC_CONFIDENCE_THRESHOLD,
    SEVERE_IOC_MIN_SCORE,
    THRESHOLD_BENIGN_MAX,
    THRESHOLD_SUSPICIOUS_MAX,
)
from app.correlation.normalizer import (
    normalize_geo_signal,
    normalize_ioc_signal,
    normalize_ml_signal,
    normalize_rules_signal,
)
from app.correlation.evidence_graph import build_evidence_graph

logger = logging.getLogger("email_forensics.correlation.engine")


class CorrelationEngine:
    """Consumes persisted records from Rules, ML, IOC, and Geo engines to generate
    the explainable Final Forensic Assessment.
    """

    disclaimer = (
        "Forensic Disclaimer: The correlation score is an explainable multi-signal risk rating "
        "synthesizing observed technical, statistical, intelligence, and network origin evidence. "
        "It is NOT a mathematically calibrated probability of fraud."
    )

    def __init__(self):
        self.version = CORRELATION_ENGINE_VERSION
        self.policy_version = CORRELATION_POLICY_VERSION

    def correlate(
        self,
        case_id: str,
        db: Session,
    ) -> CorrelationResult:
        now_str = datetime.now(timezone.utc).isoformat()
        limitations: List[str] = []
        conflicts: List[CorrelationConflict] = []

        # 1. Fetch upstream persisted records for this case_id
        case = db.query(Case).filter(Case.case_id == case_id).one_or_none()
        rule_rec = db.query(RuleResultRecord).filter(RuleResultRecord.case_id == case_id).one_or_none()
        ml_rec = db.query(MLResultRecord).filter(MLResultRecord.case_id == case_id).one_or_none()
        ioc_records = (
            db.query(IOCResultRecord)
            .filter(IOCResultRecord.case_id == case_id)
            .order_by(IOCResultRecord.id.asc())
            .all()
        )
        geo_rec = db.query(GeoOriginResultRecord).filter(GeoOriginResultRecord.case_id == case_id).one_or_none()
        parsed_rec = db.query(ParsedData).filter(ParsedData.case_id == case_id).one_or_none()
        
        # If no IOC records exist AND the case was never parsed/evaluated, IOC signal is UNAVAILABLE
        ioc_records_arg = ioc_records if (ioc_records or parsed_rec is not None) else None

        # Provenance snapshot
        upstream = UpstreamVersions(
            parser_version=parsed_rec.parser_version if parsed_rec else None,
            rules_engine_version=rule_rec.rules_engine_version if rule_rec else None,
            ml_model_version=ml_rec.model_version if ml_rec else None,
            ml_preprocessing_version=ml_rec.preprocessing_version if ml_rec else None,
            ioc_engine_version=IOC_ENGINE_VERSION if ioc_records else None,
            ioc_feed_version=ioc_records[0].feed_version if ioc_records else None,
            ioc_feed_sha256=ioc_records[0].feed_sha256 if ioc_records else None,
            geo_analysis_version=geo_rec.analysis_version if geo_rec else None,
            geo_database_version=geo_rec.geo_database_version if geo_rec else None,
            geo_database_sha256=geo_rec.geo_database_sha256 if geo_rec else None,
            network_feed_version=geo_rec.network_feed_version if geo_rec else None,
            network_feed_sha256=geo_rec.network_feed_sha256 if geo_rec else None,
            correlation_engine_version=self.version,
            correlation_policy_version=self.policy_version,
        )

        # 2. Normalize signals
        sig_rules = normalize_rules_signal(rule_rec)
        sig_ml = normalize_ml_signal(ml_rec)
        sig_ioc, has_ioc_conflict = normalize_ioc_signal(ioc_records_arg)
        sig_geo = normalize_geo_signal(geo_rec)

        engine_signals: Dict[str, EngineSignal] = {
            "rules": sig_rules,
            "ml": sig_ml,
            "ioc": sig_ioc,
            "geo": sig_geo,
        }

        # 3. Calculate coverage and renormalize weights
        available_engines = [name for name, s in engine_signals.items() if s.availability == SignalAvailability.AVAILABLE]
        sum_available_base_weights = sum(DEFAULT_ENGINE_WEIGHTS[name] for name in available_engines)
        coverage_percent = round((sum_available_base_weights / 1.0) * 100.0, 1)

        coverage = EvidenceCoverage(
            rules=sig_rules.availability,
            ml=sig_ml.availability,
            ioc=sig_ioc.availability,
            geo=sig_geo.availability,
            coverage_percent=coverage_percent,
        )

        if coverage_percent < 100.0:
            missing = [name.upper() for name, s in engine_signals.items() if s.availability != SignalAvailability.AVAILABLE]
            limitations.append(f"Incomplete engine coverage: {', '.join(missing)} signal(s) unavailable; remaining weights dynamically renormalized.")

        # Re-weight available signals
        for name, sig in engine_signals.items():
            if sig.availability == SignalAvailability.AVAILABLE and sum_available_base_weights > 0:
                sig.effective_weight = round(DEFAULT_ENGINE_WEIGHTS[name] / sum_available_base_weights, 4)
                sig.contribution = round(sig.normalized_value * sig.effective_weight * 100, 2)
            else:
                sig.effective_weight = 0.0
                sig.contribution = 0.0

        # 4. Build Evidence Graph & Detect Double Counting Overlaps
        evidence_graph = build_evidence_graph(rule_rec, ioc_records, geo_rec)
        overlap_discount_applied = 0.0

        if evidence_graph.cross_engine_entity_count > 0:
            # If multiple engines flagged the exact same IP/Domain, apply a modest sub-additive discount
            overlap_discount_applied = round(evidence_graph.cross_engine_entity_count * 2.5 * ENTITY_OVERLAP_DISCOUNT_FACTOR, 2)
            limitations.append(
                f"Double-Counting Mitigation: Identified {evidence_graph.cross_engine_entity_count} cross-engine entity overlap(s); sub-additive overlap adjustment (-{overlap_discount_applied:.1f} pts) applied to prevent artificial score inflation."
            )

        # 5. Calculate base score from available contributions
        raw_weighted_score = sum(s.contribution for s in engine_signals.values())
        final_score = max(0.0, min(100.0, raw_weighted_score - overlap_discount_applied))

        # 6. Detect Cross-Engine Conflicts
        if sig_rules.availability == SignalAvailability.AVAILABLE and sig_ml.availability == SignalAvailability.AVAILABLE:
            if sig_rules.normalized_value >= 0.60 and sig_ml.normalized_value <= 0.30:
                conflicts.append(
                    CorrelationConflict(
                        conflict_type="RULES_ML_DISAGREEMENT",
                        engines_involved=["RULES", "ML"],
                        description="Deterministic rules identified high risk technical/header patterns, but statistical ML found low probability of phishing.",
                        reconciliation="Technical header indicators prioritized for potential novel/sparse-text attack; confidence reduced.",
                    )
                )
            elif sig_rules.normalized_value <= 0.25 and sig_ml.normalized_value >= 0.70:
                conflicts.append(
                    CorrelationConflict(
                        conflict_type="RULES_ML_DISAGREEMENT",
                        engines_involved=["RULES", "ML"],
                        description="ML model detected strong phishing text semantics, but deterministic technical rules did not fire.",
                        reconciliation="Phishing text semantics recognized; elevated caution warranted.",
                    )
                )

        if has_ioc_conflict:
            conflicts.append(
                CorrelationConflict(
                    conflict_type="IOC_FEED_DISAGREEMENT",
                    engines_involved=["IOC"],
                    description="Extracted indicator matches both known malicious and known benign intelligence sources across feeds.",
                    reconciliation="Indicator flagged as disputed infrastructure; confidence reduced.",
                )
            )

        # 7. Asymmetric IOC Override: Check if verified malicious IOC exists
        severe_ioc_present = False
        if ioc_records:
            for r in ioc_records:
                if r.status == "known_malicious" and r.confidence >= SEVERE_IOC_CONFIDENCE_THRESHOLD:
                    severe_ioc_present = True
                    break

        if severe_ioc_present and final_score < SEVERE_IOC_MIN_SCORE:
            limitations.append(
                f"Asymmetric Override: Direct high-confidence threat intelligence match escalated risk score from {final_score:.1f} to {SEVERE_IOC_MIN_SCORE:.1f}."
            )
            final_score = SEVERE_IOC_MIN_SCORE

        final_score = round(final_score, 1)

        # 8. Determine Final Assessment
        if coverage_percent < MIN_COVERAGE_FOR_ASSESSMENT:
            final_assessment = FinalAssessment.INCONCLUSIVE
            limitations.append("Evidence coverage below minimum defensibility threshold (40%); assessment marked INCONCLUSIVE.")
        elif final_score >= 60.0:
            final_assessment = FinalAssessment.HIGH_RISK
        elif final_score >= 25.0:
            final_assessment = FinalAssessment.SUSPICIOUS
        else:
            final_assessment = FinalAssessment.BENIGN

        # 9. Determine Correlation Confidence
        # Independent of final score: reflects coverage, consistency, conflicts, and signal quality
        if coverage_percent >= 90.0 and not conflicts and not has_ioc_conflict:
            confidence = CorrelationConfidence.HIGH
        elif coverage_percent >= 60.0 and len(conflicts) <= 1:
            confidence = CorrelationConfidence.MEDIUM
        else:
            confidence = CorrelationConfidence.LOW

        # 10. Rank Top Contributing Evidence (5-10 items)
        top_evidence: List[TopEvidenceItem] = []
        rank = 1

        # IOC malicious hits
        if ioc_records:
            for r in ioc_records:
                if r.status == "known_malicious":
                    top_evidence.append(
                        TopEvidenceItem(
                            rank=rank,
                            engine="IOC",
                            evidence_type="threat_intel_match",
                            impact="high",
                            description=f"Matched {r.ioc_type} '{r.original_value}' in {r.source}: {r.reason}",
                        )
                    )
                    rank += 1

        # High-scoring rules
        rule_results_str = getattr(rule_rec, "results_json", None) or getattr(rule_rec, "rule_results_json", None)
        if rule_rec and rule_results_str:
            try:
                hits = json.loads(rule_results_str)
                sorted_hits = sorted([h for h in hits if h.get("fired")], key=lambda x: x.get("score", 0), reverse=True)
                for h in sorted_hits[:3]:
                    top_evidence.append(
                        TopEvidenceItem(
                            rank=rank,
                            engine="RULES",
                            evidence_type=h.get("rule_id", "rule"),
                            impact="high" if h.get("score", 0) >= 15 else "medium",
                            description=f"{h.get('title', '')} (+{h.get('score')} pts): {h.get('description', '')}",
                        )
                    )
                    rank += 1
            except Exception:
                pass

        # ML high probability
        if ml_rec and ml_rec.model_status == "ready" and ml_rec.phishing_probability >= 0.65:
            top_evidence.append(
                TopEvidenceItem(
                    rank=rank,
                    engine="ML",
                    evidence_type="phishing_probability",
                    impact="high" if ml_rec.phishing_probability >= 0.85 else "medium",
                    description=f"ML content classifier indicates {ml_rec.phishing_probability * 100:.1f}% phishing likelihood ({ml_rec.confidence} conf)",
                )
            )
            rank += 1

        # Geo Tor or VPN
        if geo_rec and geo_rec.network_intel_json:
            try:
                intel = json.loads(geo_rec.network_intel_json)
                if intel.get("is_tor_exit"):
                    top_evidence.append(
                        TopEvidenceItem(
                            rank=rank,
                            engine="GEO",
                            evidence_type="tor_routing",
                            impact="medium",
                            description=f"Origin IP {geo_rec.selected_origin_ip} is an active Tor exit node",
                        )
                    )
                    rank += 1
                elif intel.get("is_vpn"):
                    top_evidence.append(
                        TopEvidenceItem(
                            rank=rank,
                            engine="GEO",
                            evidence_type="vpn_routing",
                            impact="low",
                            description=f"Origin IP {geo_rec.selected_origin_ip} routed through commercial VPN infrastructure",
                        )
                    )
                    rank += 1
            except Exception:
                pass

        # If no positive indicators fired
        if not top_evidence:
            top_evidence.append(
                TopEvidenceItem(
                    rank=1,
                    engine="CORRELATION",
                    evidence_type="baseline_clear",
                    impact="low",
                    description="No significant malicious indicators, anomalies, or suspicious patterns detected across all intelligence engines.",
                )
            )

        # 11. Generate Analyst-Readable Explanation
        # Answers: Why? How confident? What is uncertain?
        why_parts = []
        if final_assessment == FinalAssessment.HIGH_RISK:
            why_parts.append("The email exhibits strong cumulative indicators of malicious intent across multiple intelligence layers.")
        elif final_assessment == FinalAssessment.SUSPICIOUS:
            why_parts.append("The email exhibits elevated risk indicators requiring manual analyst review.")
        elif final_assessment == FinalAssessment.BENIGN:
            why_parts.append("No actionable malicious indicators or technical anomalies were observed.")
        else:
            why_parts.append("Available forensic evidence is insufficient to reach a definitive risk classification.")

        # Engine breakdown rationale
        if sig_rules.availability == SignalAvailability.AVAILABLE and sig_rules.normalized_value >= 0.40:
            why_parts.append(f"Deterministic rules identified notable technical/header anomalies (contribution: {sig_rules.contribution:.1f} pts).")
        if sig_ml.availability == SignalAvailability.AVAILABLE and sig_ml.normalized_value >= 0.60:
            why_parts.append(f"The statistical ML model flagged phishing content semantics (probability: {sig_ml.normalized_value:.2f}).")
        if ioc_records and any(r.status == "known_malicious" for r in ioc_records):
            why_parts.append("Extracted indicators matched verified active malicious infrastructure in threat intelligence feeds.")
        if sig_geo.availability == SignalAvailability.AVAILABLE and sig_geo.normalized_value >= 0.20:
            why_parts.append("Network origin routing reflects anonymizing relay infrastructure (Tor/VPN/Hosting).")

        # Uncertainty rationale
        uncertain_parts = []
        if conflicts:
            conflict_descs = "; ".join(c.description for c in conflicts)
            uncertain_parts.append(f"Signal Discrepancy: {conflict_descs}")
        if coverage_percent < 100.0:
            uncertain_parts.append(f"Coverage: {coverage_percent:.0f}% of engines available.")

        explanation = (
            f"Assessment: {final_assessment.value} (Score: {final_score:.1f}/100, Confidence: {confidence.value}). "
            f"{' '.join(why_parts)} "
            f"{' '.join(uncertain_parts)}"
        ).strip()

        return CorrelationResult(
            case_id=case_id,
            correlation_engine_version=self.version,
            policy_version=self.policy_version,
            evaluated_timestamp=now_str,
            final_score=final_score,
            final_assessment=final_assessment,
            correlation_confidence=confidence,
            evidence_coverage=coverage,
            engine_breakdown=engine_signals,
            top_evidence=top_evidence[:10],
            evidence_graph=evidence_graph,
            conflicts=conflicts,
            limitations=limitations,
            explanation=explanation,
            upstream_versions=upstream,
        )


_default_correlation_engine: Optional[CorrelationEngine] = None


def get_correlation_engine() -> CorrelationEngine:
    global _default_correlation_engine
    if _default_correlation_engine is None:
        _default_correlation_engine = CorrelationEngine()
    return _default_correlation_engine


def evaluate_correlation(case_id: str, db: Session) -> CorrelationResult:
    """Public correlation evaluation entrypoint."""
    return get_correlation_engine().correlate(case_id, db)
