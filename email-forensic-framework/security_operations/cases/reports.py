"""
Phase 25 — Post-Incident Reporting, Root-Cause Analysis & Business Impact
Generates executive post-incident reviews, ranks root-cause candidates,
and translates technical findings into operational business impact metrics.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import time
from .cases import Case


class RootCauseCandidateEngine:
    """Evaluates and ranks evidence-backed root cause candidates."""

    @staticmethod
    def evaluate_candidates(
        case: Case,
        historical_context: Dict[str, Any],
        recent_changes: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        candidates = []

        # Candidate 1: Unauthorized or unapproved deployment change
        unapproved = not any(c.get("status") == "APPROVED" for c in recent_changes)
        if unapproved:
            candidates.append({
                "candidate": "Unapproved Service / Crypto Deployment Change",
                "evidence_strength": "STRONG",
                "confidence": 0.88,
                "justification": "Certificate or cryptographic configuration changed with no corresponding approved change ticket.",
                "evidence_items": ["NO_MATCHING_CHANGE_TICKET", f"ASSET_{case.asset_id}"],
            })

        # Candidate 2: Automated cert renewal regression
        has_cert = any("cert" in str(a).lower() for a in case.alert_ids)
        if has_cert:
            candidates.append({
                "candidate": "Automated Certificate Renewal Configuration Drift",
                "evidence_strength": "MODERATE",
                "confidence": 0.65,
                "justification": "Automated renewal script deployed a certificate or cipher configuration that violates baseline policy.",
                "evidence_items": ["CERT_ROTATION_OBSERVED"],
            })

        # Candidate 3: Adversary or unauthorized access
        if case.risk_score >= 80:
            candidates.append({
                "candidate": "Adversarial Ingress or Protocol Downgrade Attack",
                "evidence_strength": "MODERATE",
                "confidence": 0.55,
                "justification": "High dynamic risk score and rare JA4 fingerprint indicate potential active interception or downgrade.",
                "evidence_items": [f"RISK_SCORE_{case.risk_score}"],
            })
        else:
            candidates.append({
                "candidate": "Routine Configuration Drift / Operator Error",
                "evidence_strength": "WEAK",
                "confidence": 0.40,
                "justification": "Non-malicious configuration oversight during maintenance activity.",
                "evidence_items": ["DRIFT_OBSERVED"],
            })

        # Sort by confidence descending
        return sorted(candidates, key=lambda c: c["confidence"], reverse=True)


class BusinessImpactTranslator:
    """Translates technical forensic telemetry into business operational impact."""

    @staticmethod
    def assess_impact(
        asset_id: str,
        affected_services: List[str],
        client_failures: int,
        duration_minutes: float,
    ) -> Dict[str, Any]:
        impact_level = "LOW"
        if client_failures > 5 or len(affected_services) > 3 or duration_minutes > 60:
            impact_level = "HIGH"
        elif client_failures > 0 or len(affected_services) > 1:
            impact_level = "MEDIUM"

        return {
            "impact_level": impact_level,
            "affected_asset": asset_id,
            "affected_services": affected_services,
            "client_invalidation_count": client_failures,
            "estimated_downtime_minutes": round(duration_minutes, 1),
            "business_impact_summary": (
                f"{impact_level} impact: {len(affected_services)} services degraded, "
                f"{client_failures} client endpoints impacted over {round(duration_minutes, 1)} minutes."
            ),
        }


class PostIncidentReportGenerator:
    """Produces the structured canonical post-mortem incident report."""

    @staticmethod
    def generate_report(
        case: Case,
        root_causes: List[Dict[str, Any]],
        business_impact: Dict[str, Any],
        actions_taken: List[Dict[str, Any]],
        verification_result: Dict[str, Any],
        lessons_learned: Optional[List[str]] = None,
        detection_improvements: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        duration = 0.0
        if case.closed_at:
            duration = max(0.0, (case.closed_at - case.created_at) / 60.0)

        return {
            "report_id": f"PIR-{case.case_id}",
            "case_id": case.case_id,
            "generated_at": time.time(),
            "iso_time": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "title": case.title,
                "description": case.description,
                "status": case.status.value,
                "priority": case.priority.value,
                "risk_score": case.risk_score,
                "asset_id": case.asset_id,
                "tenant_id": case.tenant_id,
                "duration_minutes": round(duration, 1),
            },
            "root_cause_analysis": {
                "primary_root_cause": root_causes[0]["candidate"] if root_causes else "Unknown",
                "candidates": root_causes,
            },
            "business_impact": business_impact,
            "actions_executed": actions_taken,
            "verification": verification_result,
            "lessons_learned": lessons_learned or [
                "Ensure automated certificate renewals enforce pre-deployment policy checks.",
                "Tighten change-ticket association to prevent unverified out-of-band updates.",
            ],
            "detection_improvements": detection_improvements or [
                "Tune rule alerting threshold to exclude scheduled maintenance windows.",
                "Promote observed JA4 anomaly signature into continuous canary detection.",
            ],
        }
