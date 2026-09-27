"""
Phase 23 - Validation Datasets.
Curates positive, negative, edge, and synthetic datasets for continuous detection testing.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any

@dataclass
class LabeledEvent:
    event_id: str
    data: Dict[str, Any]
    label: str  # POSITIVE, NEGATIVE, EDGE_CASE, SYNTHETIC
    expected_rule_triggers: List[str] = field(default_factory=list)

class ValidationDatasetRepository:
    """Manages ground-truth corpora for rule testing."""

    @classmethod
    def get_tls_test_dataset(cls) -> List[LabeledEvent]:
        return [
            # Positive: Obvious deprecated TLS 1.0 on mail server
            LabeledEvent(
                event_id="VAL-POS-01",
                data={"asset": "MTA-07", "tls_version": "TLS 1.0", "ja4": "JA4-LEGACY", "ja4_rarity": 0.01},
                label="POSITIVE",
                expected_rule_triggers=["DET-TLS-001"]
            ),
            # Positive: Deprecated TLS 1.1 with rare JA4
            LabeledEvent(
                event_id="VAL-POS-02",
                data={"asset": "MTA-02", "tls_version": "TLS 1.1", "ja4": "JA4-ATTACK", "ja4_rarity": 0.005},
                label="POSITIVE",
                expected_rule_triggers=["DET-TLS-001"]
            ),
            # Negative: Standard modern TLS 1.3
            LabeledEvent(
                event_id="VAL-NEG-01",
                data={"asset": "MTA-01", "tls_version": "TLS 1.3", "ja4": "JA4-OFFICIAL", "ja4_rarity": 0.85},
                label="NEGATIVE",
                expected_rule_triggers=[]
            ),
            # Negative: Approved TLS 1.2
            LabeledEvent(
                event_id="VAL-NEG-02",
                data={"asset": "MTA-03", "tls_version": "TLS 1.2", "ja4": "JA4-STANDARD", "ja4_rarity": 0.60},
                label="NEGATIVE",
                expected_rule_triggers=[]
            ),
            # Edge Case: Minor fallback TLS 1.2 with rare cipher
            LabeledEvent(
                event_id="VAL-EDGE-01",
                data={"asset": "MTA-08", "tls_version": "TLS 1.2", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "ja4_rarity": 0.03},
                label="EDGE_CASE",
                expected_rule_triggers=["DET-CIPHER-001"]
            )
        ]
