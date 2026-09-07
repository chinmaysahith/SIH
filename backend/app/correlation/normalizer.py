"""Signal Normalization Module for Stage 7.

Normalizes raw results from Rules, ML, IOC, and Geo engines into a unified [0.0, 1.0] scale.
"""

import json
from typing import List, Optional, Tuple
from app.db.models import GeoOriginResultRecord, IOCResultRecord, MLResultRecord, RuleResultRecord
from app.correlation.models import EngineSignal, SignalAvailability
from app.correlation.policy import DEFAULT_ENGINE_WEIGHTS


def normalize_rules_signal(rule_rec: Optional[RuleResultRecord]) -> EngineSignal:
    base_weight = DEFAULT_ENGINE_WEIGHTS["rules"]
    if not rule_rec:
        return EngineSignal(
            engine_name="rules",
            availability=SignalAvailability.UNAVAILABLE,
            raw_value=None,
            normalized_value=0.0,
            base_weight=base_weight,
            effective_weight=0.0,
            contribution=0.0,
            summary_text="Rules Engine evaluation unavailable",
        )

    # Rules total_score is capped at 100 in Stage 3
    total_score = max(0.0, min(100.0, float(rule_rec.total_score)))
    normalized = round(total_score / 100.0, 4)

    return EngineSignal(
        engine_name="rules",
        availability=SignalAvailability.AVAILABLE,
        raw_value={"total_score": total_score, "verdict": rule_rec.rules_verdict},
        normalized_value=normalized,
        base_weight=base_weight,
        effective_weight=base_weight,
        contribution=round(normalized * base_weight * 100, 2),
        summary_text=f"Deterministic rules score {int(total_score)}/100 ({rule_rec.rules_verdict})",
    )


def normalize_ml_signal(ml_rec: Optional[MLResultRecord]) -> EngineSignal:
    base_weight = DEFAULT_ENGINE_WEIGHTS["ml"]
    if not ml_rec:
        return EngineSignal(
            engine_name="ml",
            availability=SignalAvailability.UNAVAILABLE,
            raw_value=None,
            normalized_value=0.0,
            base_weight=base_weight,
            effective_weight=0.0,
            contribution=0.0,
            summary_text="ML Engine evaluation unavailable",
        )

    # Check model status
    if ml_rec.model_status != "ready":
        return EngineSignal(
            engine_name="ml",
            availability=SignalAvailability.UNAVAILABLE,
            raw_value={"model_status": ml_rec.model_status},
            normalized_value=0.0,
            base_weight=base_weight,
            effective_weight=0.0,
            contribution=0.0,
            summary_text=f"ML model offline or text insufficient ({ml_rec.model_status})",
        )

    prob = max(0.0, min(1.0, float(ml_rec.phishing_probability)))
    normalized = round(prob, 4)

    return EngineSignal(
        engine_name="ml",
        availability=SignalAvailability.AVAILABLE,
        raw_value={
            "phishing_probability": prob,
            "prediction": ml_rec.prediction,
            "confidence": ml_rec.confidence,
        },
        normalized_value=normalized,
        base_weight=base_weight,
        effective_weight=base_weight,
        contribution=round(normalized * base_weight * 100, 2),
        summary_text=f"ML phishing probability {prob:.2f} ({ml_rec.prediction}, {ml_rec.confidence} conf)",
    )


def normalize_ioc_signal(ioc_records: Optional[List[IOCResultRecord]]) -> Tuple[EngineSignal, bool]:
    """Normalizes IOC evaluation.

    Returns:
        (EngineSignal, has_ioc_conflict)
    """
    base_weight = DEFAULT_ENGINE_WEIGHTS["ioc"]
    if ioc_records is None:
        return (
            EngineSignal(
                engine_name="ioc",
                availability=SignalAvailability.UNAVAILABLE,
                raw_value=None,
                normalized_value=0.0,
                base_weight=base_weight,
                effective_weight=0.0,
                contribution=0.0,
                summary_text="IOC Engine evaluation unavailable",
            ),
            False,
        )

    if not ioc_records:
        # 0 IOCs extracted from email
        return (
            EngineSignal(
                engine_name="ioc",
                availability=SignalAvailability.AVAILABLE,
                raw_value={"matched": 0, "total": 0},
                normalized_value=0.0,
                base_weight=base_weight,
                effective_weight=base_weight,
                contribution=0.0,
                summary_text="No extractable indicators observed in message",
            ),
            False,
        )

    malicious_recs = [r for r in ioc_records if r.status == "known_malicious"]
    suspicious_recs = [r for r in ioc_records if r.status == "known_suspicious"]
    benign_recs = [r for r in ioc_records if r.status == "known_benign"]

    # Detect cross-feed conflict (e.g., indicator flagged malicious by Feed A but benign by Feed B)
    has_conflict = False
    if malicious_recs and benign_recs:
        # Check if same indicator value was marked both malicious and benign
        mal_vals = {r.normalized_value for r in malicious_recs}
        ben_vals = {r.normalized_value for r in benign_recs}
        if mal_vals.intersection(ben_vals):
            has_conflict = True

    if malicious_recs:
        max_conf = max((r.confidence for r in malicious_recs), default=80)
        # Scale between 0.85 and 1.0 based on feed confidence
        normalized = round(0.85 + (max_conf / 100.0) * 0.15, 4)
        summary = f"{len(malicious_recs)} indicator(s) matched known malicious threat feeds"
    elif suspicious_recs:
        max_conf = max((r.confidence for r in suspicious_recs), default=60)
        normalized = round(0.50 + (max_conf / 100.0) * 0.15, 4)
        summary = f"{len(suspicious_recs)} indicator(s) matched known suspicious threat feeds"
    elif benign_recs:
        normalized = 0.05  # Weak negative/benign context
        summary = f"{len(benign_recs)} indicator(s) matched verified benign feeds"
    else:
        # All not_found
        normalized = 0.0
        summary = f"{len(ioc_records)} indicator(s) extracted; not present in local threat feeds (not_found != benign)"

    return (
        EngineSignal(
            engine_name="ioc",
            availability=SignalAvailability.AVAILABLE,
            raw_value={
                "total": len(ioc_records),
                "malicious": len(malicious_recs),
                "suspicious": len(suspicious_recs),
                "benign": len(benign_recs),
                "has_conflict": has_conflict,
            },
            normalized_value=normalized,
            base_weight=base_weight,
            effective_weight=base_weight,
            contribution=round(normalized * base_weight * 100, 2),
            summary_text=summary,
        ),
        has_conflict,
    )


def normalize_geo_signal(geo_rec: Optional[GeoOriginResultRecord]) -> EngineSignal:
    base_weight = DEFAULT_ENGINE_WEIGHTS["geo"]
    if not geo_rec:
        return EngineSignal(
            engine_name="geo",
            availability=SignalAvailability.UNAVAILABLE,
            raw_value=None,
            normalized_value=0.0,
            base_weight=base_weight,
            effective_weight=0.0,
            contribution=0.0,
            summary_text="Geo / Origin Forensics evaluation unavailable",
        )

    if not geo_rec.selected_origin_ip or geo_rec.confidence == "UNKNOWN":
        return EngineSignal(
            engine_name="geo",
            availability=SignalAvailability.AVAILABLE,
            raw_value={"selected_origin_ip": None, "confidence": geo_rec.confidence},
            normalized_value=0.0,
            base_weight=base_weight,
            effective_weight=base_weight,
            contribution=0.0,
            summary_text="No routable public network origin candidate observed",
        )

    # Extract network intel flags
    is_tor = False
    is_vpn = False
    is_proxy = False
    is_hosting = False

    if geo_rec.network_intel_json:
        try:
            intel = json.loads(geo_rec.network_intel_json)
            is_tor = bool(intel.get("is_tor_exit"))
            is_vpn = bool(intel.get("is_vpn"))
            is_proxy = bool(intel.get("is_proxy"))
            is_hosting = bool(intel.get("is_datacenter_hosting"))
        except Exception:
            pass

    # Contextual risk score
    context_score = 0.0
    tags = []
    if is_tor:
        context_score += 0.40
        tags.append("Tor Exit")
    if is_vpn or is_proxy:
        context_score += 0.25
        tags.append("VPN/Proxy")
    if is_hosting and not is_tor:
        context_score += 0.15
        tags.append("Datacenter Hosting")

    # Modulate by Stage 6 origin confidence
    conf_mult = {"HIGH": 1.0, "MEDIUM": 0.60, "LOW": 0.25, "UNKNOWN": 0.0}.get(
        geo_rec.confidence, 0.25
    )
    normalized = round(min(1.0, context_score * conf_mult), 4)

    summary = (
        f"Origin {geo_rec.selected_origin_ip} ({', '.join(tags) if tags else 'standard routing'}, "
        f"{geo_rec.confidence} origin confidence)"
    )

    return EngineSignal(
        engine_name="geo",
        availability=SignalAvailability.AVAILABLE,
        raw_value={
            "selected_origin_ip": geo_rec.selected_origin_ip,
            "origin_confidence": geo_rec.confidence,
            "is_tor": is_tor,
            "is_vpn": is_vpn,
            "is_proxy": is_proxy,
            "is_hosting": is_hosting,
        },
        normalized_value=normalized,
        base_weight=base_weight,
        effective_weight=base_weight,
        contribution=round(normalized * base_weight * 100, 2),
        summary_text=summary,
    )
