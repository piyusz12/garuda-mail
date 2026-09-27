"""
Phase 23 - Threat Hunting Engine.
Executes HQL queries across Lakehouse historical data, enriches candidates, and manages Hunt Knowledge Base.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
import uuid
import time
import logging

from .dsl import HQLParser, HuntQueryAST
from .planner import HuntQueryPlanner, ExecutionPlan
from .scheduler import HuntScheduler, HuntRunRecord
from .templates import HUNT_TEMPLATES

logger = logging.getLogger("Phase23-ThreatHuntingEngine")

@dataclass
class HuntCandidate:
    candidate_id: str
    hunt_id: str
    asset_id: str
    timestamp: datetime
    evidence_data: Dict[str, Any]
    risk_context: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    converted_to_finding: bool = False


@dataclass
class HuntKnowledgeItem:
    hunt_id: str
    question: str
    validated_queries: List[str]
    useful_fields: List[str]
    lessons_learned: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatHuntingEngine:
    """Core Threat Hunting Engine interfacing with Phase 22 Lakehouse."""

    def __init__(self, scheduler: Optional[HuntScheduler] = None, data_lake: Any = None):
        self.scheduler = scheduler or HuntScheduler()
        self.data_lake = data_lake  # Phase 22 ForensicDataLake or internal mock store
        self.candidates: Dict[str, HuntCandidate] = {}
        self.knowledge_base: Dict[str, HuntKnowledgeItem] = {}
        self._init_knowledge_base()

    def _init_knowledge_base(self):
        self.knowledge_base["HUNT-KB-01"] = HuntKnowledgeItem(
            hunt_id="legacy_tls_recurrence",
            question="Find recurring TLS 1.0/1.1 regressions after remediation.",
            validated_queries=["HUNT legacy_tls_recurrence FROM tls_events WHERE tls_version IN ['TLS 1.0', 'TLS 1.1'] WITHIN 90d"],
            useful_fields=["tls_version", "asset", "remediation_active", "timestamp"],
            lessons_learned="Legacy mail clients re-enable TLS 1.0 when automatic fallback is configured on perimeter relays."
        )

    def execute_hunt_query(self, query_str: str, hunt_id: Optional[str] = None) -> Tuple[HuntRunRecord, List[HuntCandidate]]:
        """Parses, plans, and executes an HQL threat hunt across Lakehouse data."""
        start_t = time.perf_counter()
        ast = HQLParser.parse(query_str)
        hunt_id = hunt_id or ast.hunt_name
        plan = HuntQueryPlanner.create_plan(ast)

        # Query Lakehouse objects
        raw_matches = self._scan_lakehouse(plan)
        
        # Candidate enrichment and scoring
        enriched_candidates = []
        for raw_obj in raw_matches:
            cand = self._enrich_candidate(hunt_id, raw_obj)
            self.candidates[cand.candidate_id] = cand
            enriched_candidates.append(cand)

        runtime_ms = (time.perf_counter() - start_t) * 1000.0
        data_range = ast.within_window or "ALL_HISTORY"

        record = self.scheduler.record_run(
            hunt_id=hunt_id,
            query=query_str,
            data_range=data_range,
            results_count=len(enriched_candidates),
            runtime_ms=runtime_ms,
            cost_units=plan.estimated_cost_units,
            start_time=datetime.now(timezone.utc)
        )
        return record, enriched_candidates

    def _scan_lakehouse(self, plan: ExecutionPlan) -> List[Dict[str, Any]]:
        """Scans lakehouse storage applying plan filters."""
        results = []
        
        # If attached to Phase 22 ForensicDataLake
        if self.data_lake and hasattr(self.data_lake, "storage"):
            for obj in self.data_lake.storage.values():
                if getattr(obj, "is_deleted", False):
                    continue
                if plan.target_layers and obj.layer not in plan.target_layers:
                    continue
                if plan.target_entity and not (
                    obj.entity_type.lower().startswith(plan.target_entity.lower()) or 
                    plan.target_entity.lower().startswith(obj.entity_type.lower())
                ):
                    continue
                if plan.time_cutoff and obj.timestamp < plan.time_cutoff:
                    continue
                
                # Check condition filters
                data = obj.data
                matched = True
                for cond in plan.event_filters:
                    field_val = data.get(cond.field)
                    if cond.operator in ("=", "=="):
                        if str(field_val).lower() != str(cond.value).lower():
                            matched = False; break
                    elif cond.operator == "IN":
                        expected_list = [str(x).lower() for x in cond.value]
                        if str(field_val).lower() not in expected_list:
                            matched = False; break
                    elif cond.operator in ("<", "<="):
                        try:
                            if float(field_val or 0) > float(cond.value):
                                matched = False; break
                        except (ValueError, TypeError):
                            matched = False; break
                if matched:
                    results.append({"object_id": obj.object_id, "timestamp": obj.timestamp, "data": obj.data})

        return results

    def _enrich_candidate(self, hunt_id: str, raw_obj: Dict[str, Any]) -> HuntCandidate:
        data = raw_obj.get("data", {})
        asset_id = data.get("asset", data.get("asset_id", "UNKNOWN-MTA"))

        # Enrichment contextual factors
        criticality = 0.9 if "07" in asset_id or "gateway" in asset_id.lower() else 0.5
        ja4 = data.get("ja4", "JA4-UNKNOWN")
        is_rare_ja4 = "NEW" in str(ja4) or float(data.get("ja4_rarity", 1.0)) < 0.05
        cert_changed = bool(data.get("certificate_changed", False))
        
        risk_context = {
            "asset_criticality": criticality,
            "ja4_fingerprint": ja4,
            "ja4_is_rare": is_rare_ja4,
            "certificate_rotated_recently": cert_changed,
            "historical_anomaly_rate": 0.15,
            "baseline_deviation": 2.4 if is_rare_ja4 else 0.2
        }

        # Calculate confidence
        confidence = 0.5
        if criticality > 0.7: confidence += 0.15
        if is_rare_ja4: confidence += 0.20
        if cert_changed: confidence += 0.15
        confidence = min(0.95, round(confidence, 2))

        cand_id = f"CAND-{uuid.uuid4().hex[:6].upper()}"
        return HuntCandidate(
            candidate_id=cand_id,
            hunt_id=hunt_id,
            asset_id=asset_id,
            timestamp=raw_obj.get("timestamp", datetime.now(timezone.utc)),
            evidence_data=data,
            risk_context=risk_context,
            confidence=confidence
        )

    def propose_autonomous_hunt(self, observed_anomalies: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        AI-driven autonomous hunt proposal based on recently clustered anomalies.
        """
        if not observed_anomalies:
            return None

        # Identify anomalous attributes (e.g. repeated new JA4 or cert changes)
        ja4_set = {a.get("ja4") for a in observed_anomalies if a.get("ja4")}
        assets = {a.get("asset") for a in observed_anomalies if a.get("asset")}

        if len(ja4_set) >= 1 and len(assets) >= 1:
            proposed_query = f"HUNT autonomous_investigation FROM tls_events WHERE ja4.rarity < 0.05 WITHIN 14d"
            return {
                "observation": f"Unusual fingerprint activity observed across {len(assets)} assets ({', '.join(list(assets)[:3])}).",
                "proposed_hunt_id": f"AUTO-HUNT-{uuid.uuid4().hex[:4].upper()}",
                "query": proposed_query,
                "target_assets": list(assets),
                "rationale": "Correlate rare client fingerprints with recent certificate or TLS configuration drift."
            }
        return None
