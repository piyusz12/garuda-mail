"""
Phase 24 — Remediation Verification Engine (Components 23, 24, 50)
Coordinates multi-layer verification across configuration, network telemetry, and service recovery health.
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional
import time

from verification.config import ConfigVerifier
from verification.telemetry import TelemetryVerifier
from verification.recovery import RecoveryEngine


@dataclass
class MultiLayerVerificationReport:
    asset_id: str
    all_layers_passed: bool
    config_result: Dict[str, Any]
    telemetry_result: Dict[str, Any]
    recovery_result: Dict[str, Any]
    timestamp: float
    verdict: str  # PASS, FAIL, PARTIAL

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RemediationVerificationEngine:
    """Consolidates verification checks into a single definitive verdict for incident progression."""

    @classmethod
    def verify_remediation(
        cls,
        asset_id: str,
        connector_registry: Any,
        observed_telemetry_sessions: Optional[List[Dict[str, Any]]] = None
    ) -> MultiLayerVerificationReport:
        # Layer 1: Configuration state
        cfg_res = ConfigVerifier.verify_config_state(asset_id, connector_registry)

        # Layer 2: Network telemetry (Zero legacy sessions)
        tel_res = TelemetryVerifier.verify_observed_telemetry(
            asset_id=asset_id,
            prohibited_protocols=["TLS 1.0", "TLS 1.1", "PLAINTEXT"],
            observed_sessions=observed_telemetry_sessions or []
        )

        # Layer 3: Recovery & service health
        rec_res = RecoveryEngine.evaluate_recovery_health(asset_id)

        all_passed = cfg_res["passed"] and tel_res["passed"] and rec_res["passed"]
        verdict = "PASS" if all_passed else ("PARTIAL" if cfg_res["passed"] else "FAIL")

        return MultiLayerVerificationReport(
            asset_id=asset_id,
            all_layers_passed=all_passed,
            config_result=cfg_res,
            telemetry_result=tel_res,
            recovery_result=rec_res,
            timestamp=time.time(),
            verdict=verdict
        )
