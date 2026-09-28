"""
Phase 23 - False Negative Analysis & Detection Gap Discovery.
Analyzes historical confirmed incidents to identify unmonitored attack paths.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any
import uuid

@dataclass
class DetectionGap:
    gap_id: str
    incident_id: str
    observed_attack_behavior: str
    expected_rule_type: str
    triggered_rules: List[str]
    missing_capabilities: List[str]
    remediation_proposal: str
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class DetectionGapDiscoveryEngine:
    """Discovers blind spots by contrasting historical incidents against detection logs."""

    @classmethod
    def analyze_incident_coverage(
        cls,
        incident_id: str,
        incident_telemetry: List[Dict[str, Any]],
        actual_triggered_rule_ids: List[str],
        expected_behaviors: List[str]
    ) -> List[DetectionGap]:
        gaps = []

        # Check if STARTTLS stripping was present in telemetry but no starttls rule triggered
        has_starttls_strip = any(t.get("starttls_stripped") for t in incident_telemetry)
        if has_starttls_strip and not any("STARTTLS" in r for r in actual_triggered_rule_ids):
            gap_id = f"GAP-{uuid.uuid4().hex[:6].upper()}"
            gaps.append(DetectionGap(
                gap_id=gap_id,
                incident_id=incident_id,
                observed_attack_behavior="Cleartext STARTTLS stripping in SMTP handshake",
                expected_rule_type="PROTOCOL_DOWNGRADE",
                triggered_rules=actual_triggered_rule_ids,
                missing_capabilities=["DET-STARTTLS-001"],
                remediation_proposal="Deploy signature rule DET-STARTTLS-001 on edge relay sensors."
            ))

        # Check JA4 rarity shift
        has_rare_ja4 = any(t.get("ja4_rarity", 1.0) < 0.05 for t in incident_telemetry)
        if has_rare_ja4 and not any("JA4" in r for r in actual_triggered_rule_ids):
            gap_id = f"GAP-{uuid.uuid4().hex[:6].upper()}"
            gaps.append(DetectionGap(
                gap_id=gap_id,
                incident_id=incident_id,
                observed_attack_behavior="Rare client fingerprint outbreak",
                expected_rule_type="ANOMALY",
                triggered_rules=actual_triggered_rule_ids,
                missing_capabilities=["DET-JA4-RARE"],
                remediation_proposal="Deploy anomaly detection model on client JA4 distributions."
            ))

        return gaps
