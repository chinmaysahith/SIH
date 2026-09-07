"""Evidence Graph & Entity Overlap Resolver for Stage 7 Correlation.

Maps observed indicators to entities (IP, DOMAIN, URL, HASH) across engines to
detect multiple engines observing the same physical or network infrastructure,
preventing artificial score inflation from double-counting.
"""

import json
import re
from typing import Dict, List, Optional
from app.db.models import GeoOriginResultRecord, IOCResultRecord, RuleResultRecord
from app.correlation.models import EvidenceEntity, EvidenceGraph, EvidenceObservation


def build_evidence_graph(
    rule_rec: Optional[RuleResultRecord],
    ioc_records: List[IOCResultRecord],
    geo_rec: Optional[GeoOriginResultRecord],
) -> EvidenceGraph:
    entities_map: Dict[str, EvidenceEntity] = {}

    def get_or_create_entity(entity_type: str, val: str) -> EvidenceEntity:
        clean_val = val.strip().lower()
        key = f"{entity_type}:{clean_val}"
        if key not in entities_map:
            entities_map[key] = EvidenceEntity(
                entity_id=key,
                entity_type=entity_type,
                value=clean_val,
                observations=[],
                is_cross_engine=False,
            )
        return entities_map[key]

    # 1. Map IOC observations
    for r in ioc_records:
        entity_type = r.ioc_type.upper()
        ent = get_or_create_entity(entity_type, r.normalized_value)
        ent.observations.append(
            EvidenceObservation(
                engine="IOC",
                observation_type=f"ioc_{r.status}",
                indicator_value=r.normalized_value,
                severity="critical" if r.status == "known_malicious" else "medium" if r.status == "known_suspicious" else "info",
                details=f"{r.source} ({r.confidence}%): {r.reason}",
            )
        )

        # If it's a URL, also associate the domain entity
        if entity_type == "URL":
            m = re.search(r"https?://([^/:\?#]+)", r.normalized_value)
            if m:
                domain_val = m.group(1)
                dom_ent = get_or_create_entity("DOMAIN", domain_val)
                dom_ent.observations.append(
                    EvidenceObservation(
                        engine="IOC",
                        observation_type="url_host_component",
                        indicator_value=domain_val,
                        severity="info",
                        details=f"Host component of URL {r.normalized_value}",
                    )
                )

    # 2. Map Geo / Origin observations
    if geo_rec and geo_rec.selected_origin_ip:
        ip_val = geo_rec.selected_origin_ip.strip().lower()
        ent = get_or_create_entity("IP", ip_val)
        intel_desc = []
        if geo_rec.network_intel_json:
            try:
                intel = json.loads(geo_rec.network_intel_json)
                if intel.get("is_tor_exit"):
                    intel_desc.append("Tor Exit Node")
                if intel.get("is_vpn"):
                    intel_desc.append("Commercial VPN")
                if intel.get("is_proxy"):
                    intel_desc.append("Proxy Relay")
                if intel.get("is_datacenter_hosting"):
                    intel_desc.append("Datacenter Hosting")
            except Exception:
                pass

        ent.observations.append(
            EvidenceObservation(
                engine="GEO",
                observation_type="origin_hop",
                indicator_value=ip_val,
                severity="medium" if intel_desc else "info",
                details=f"Selected Origin IP (Conf: {geo_rec.confidence}). Flags: {', '.join(intel_desc) if intel_desc else 'Normal'}",
            )
        )

    # 3. Map Rules observations (extract rule hits from rule_rec if present)
    rule_results_str = getattr(rule_rec, "results_json", None) or getattr(rule_rec, "rule_results_json", None)
    if rule_rec and rule_results_str:
        try:
            hits = json.loads(rule_results_str)
            for h in hits:
                if not h.get("fired"):
                    continue
                rule_id = h.get("rule_id", "UNKNOWN_RULE")
                evidence = h.get("evidence", {})

                # If rule identified IP host in URL
                if rule_id == "RULE-URL-003" and "urls" in evidence:
                    for u in evidence.get("urls", []):
                        m = re.search(r"https?://([^/:\?#]+)", u)
                        if m:
                            host_val = m.group(1)
                            # Check if host is IPv4
                            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_val):
                                ent = get_or_create_entity("IP", host_val)
                                ent.observations.append(
                                    EvidenceObservation(
                                        engine="RULES",
                                        observation_type="ip_host_in_url",
                                        indicator_value=host_val,
                                        severity="medium",
                                        details=f"URL with raw IP address host detected ({rule_id})",
                                    )
                                )
                elif "domain" in evidence:
                    dom_val = evidence["domain"]
                    ent = get_or_create_entity("DOMAIN", dom_val)
                    ent.observations.append(
                        EvidenceObservation(
                            engine="RULES",
                            observation_type="sender_domain_anomaly",
                            indicator_value=dom_val,
                            severity="medium",
                            details=f"Fired {rule_id}: {h.get('description', '')}",
                        )
                    )
        except Exception:
            pass

    # Mark entities that have observations from 2 or more distinct engines
    cross_engine_count = 0
    for ent in entities_map.values():
        engines_involved = {obs.engine for obs in ent.observations}
        if len(engines_involved) >= 2:
            ent.is_cross_engine = True
            cross_engine_count += 1

    return EvidenceGraph(
        entities=list(entities_map.values()),
        cross_engine_entity_count=cross_engine_count,
    )
