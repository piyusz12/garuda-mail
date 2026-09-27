"""
Phase 23 - Autonomous Hypothesis Generator and Data Model.
Generates testable security hypotheses from findings, hunts, and peer anomalies.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import uuid

@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    status: str = "OPEN"  # OPEN, TESTING, SUPPORTED, UNSUPPORTED, RESOLVED
    confidence: float = 0.5
    supporting_evidence: List[str] = field(default_factory=list)
    counter_evidence: List[str] = field(default_factory=list)
    decomposed_confidence: Dict[str, float] = field(default_factory=dict)
    target_assets: List[str] = field(default_factory=list)
    entities: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class HypothesisGenerator:
    """Proposes hypotheses from forensic candidates and anomalies."""

    @classmethod
    def generate_from_candidate(cls, candidate: Any) -> Hypothesis:
        risk = getattr(candidate, "risk_context", {})
        asset = getattr(candidate, "asset_id", "MTA-UNKNOWN")
        ja4 = risk.get("ja4_fingerprint", "JA4-UNKNOWN")
        
        statement = (
            f"Client fingerprint {ja4} on asset {asset} may represent unauthorized or altered MTA client software "
            f"correlated with recent certificate transitions."
        )
        hyp_id = f"HYP-{uuid.uuid4().hex[:6].upper()}"
        
        return Hypothesis(
            hypothesis_id=hyp_id,
            statement=statement,
            status="OPEN",
            confidence=getattr(candidate, "confidence", 0.6),
            supporting_evidence=[f"CANDIDATE-{getattr(candidate, 'candidate_id', '001')}"],
            target_assets=[asset],
            entities={"ja4": ja4, "asset": asset}
        )

    @classmethod
    def generate_peer_deviation_hypothesis(cls, asset_id: str, metric: str, z_score: float) -> Hypothesis:
        hyp_id = f"HYP-{uuid.uuid4().hex[:6].upper()}"
        statement = (
            f"Asset {asset_id} exhibits an abnormal statistical deviation in '{metric}' (Z-Score: {z_score:.2f}) "
            f"relative to its baseline peer group."
        )
        return Hypothesis(
            hypothesis_id=hyp_id,
            statement=statement,
            status="OPEN",
            confidence=0.7,
            target_assets=[asset_id],
            entities={"asset": asset_id, "metric": metric, "z_score": z_score}
        )
