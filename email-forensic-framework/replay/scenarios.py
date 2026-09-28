"""
Phase 23 - Attack Replay Scenarios.
Defines multi-stage, reproducible adversarial scenarios for testing the platform.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any

@dataclass
class ScenarioEvent:
    event_id: str
    event_type: str
    asset: str
    offset_seconds: int
    data: Dict[str, Any]

@dataclass
class AttackScenario:
    scenario_id: str
    name: str
    description: str
    target_assets: List[str]
    events: List[ScenarioEvent]
    expected_detections: List[str]


def get_scenario_007() -> AttackScenario:
    """
    SCENARIO-007:
    1. Certificate change on MTA
    2. New rare JA4 appears
    3. TLS protocol downgrade to TLS 1.1
    4. Repeated sessions established
    """
    return AttackScenario(
        scenario_id="SCENARIO-007",
        name="Coordinated Man-in-the-Middle Downgrade",
        description="Adversary rotates certificate, injects rogue client JA4, and forces TLS 1.1 fallback.",
        target_assets=["MTA-07"],
        events=[
            ScenarioEvent(
                event_id="SCEN-007-EVT-01",
                event_type="CERT_CHANGE",
                asset="MTA-07",
                offset_seconds=0,
                data={"asset": "MTA-07", "certificate_changed": True, "cert_thumbprint": "THUMB-ROGUE-99"}
            ),
            ScenarioEvent(
                event_id="SCEN-007-EVT-02",
                event_type="NEW_JA4",
                asset="MTA-07",
                offset_seconds=600,  # +10 minutes
                data={"asset": "MTA-07", "ja4": "JA4-ROGUE-EXPLOIT", "ja4_rarity": 0.001}
            ),
            ScenarioEvent(
                event_id="SCEN-007-EVT-03",
                event_type="TLS_DOWNGRADE",
                asset="MTA-07",
                offset_seconds=7200,  # +2 hours
                data={"asset": "MTA-07", "tls_version": "TLS 1.1", "ja4": "JA4-ROGUE-EXPLOIT", "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA"}
            ),
            ScenarioEvent(
                event_id="SCEN-007-EVT-04",
                event_type="REPEATED_SESSION",
                asset="MTA-07",
                offset_seconds=86400,  # +1 day
                data={"asset": "MTA-07", "session_count": 42, "tls_version": "TLS 1.1"}
            )
        ],
        expected_detections=["DET-TLS-001", "DET-221"]
    )
