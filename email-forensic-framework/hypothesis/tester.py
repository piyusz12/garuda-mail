"""
Phase 23 - Hypothesis Tester.
Executes formal validation of hypotheses against historical lakehouse data, peer groups, and counter-evidence.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from .generator import Hypothesis
from .evidence import EvidenceCollector
from .counterevidence import CounterEvidenceEngine
from detection.scoring import DetectionScorer

class HypothesisTester:
    """Executes empirical tests on security hypotheses."""

    @classmethod
    def test_hypothesis(
        cls,
        hypothesis: Hypothesis,
        lakehouse: Any,
        approved_deployments: List[Dict[str, Any]] = None,
        known_vendor_fingerprints: List[str] = None
    ) -> Hypothesis:
        hypothesis.status = "TESTING"
        hypothesis.updated_at = datetime.now(timezone.utc)

        ja4 = hypothesis.entities.get("ja4", "")
        asset = hypothesis.entities.get("asset", "")

        # 1. Collect positive evidence
        pos_evidence = EvidenceCollector.collect_for_asset_ja4(lakehouse, asset, ja4)
        for ev in pos_evidence:
            hypothesis.supporting_evidence.append(ev["evidence_id"])

        # 2. Search counter-evidence
        counter_statements, counter_factor = CounterEvidenceEngine.evaluate_counter_evidence(
            lakehouse=lakehouse,
            asset_id=asset,
            ja4_fingerprint=ja4,
            approved_deployments=approved_deployments,
            known_vendor_fingerprints=known_vendor_fingerprints
        )
        hypothesis.counter_evidence.extend(counter_statements)

        # 3. Calculate decomposed confidence
        hist_support = 0.85 if len(pos_evidence) > 0 else 0.40
        beh_support = 0.80 if not counter_statements else 0.50
        decomp = DetectionScorer.decompose_confidence(
            historical_support=hist_support,
            behavioral_support=beh_support,
            graph_support=0.75,
            intelligence_support=0.70,
            counter_evidence=counter_factor
        )
        hypothesis.decomposed_confidence = decomp
        hypothesis.confidence = decomp["net_confidence"]

        # 4. Status determination
        if hypothesis.confidence >= 0.65 and len(hypothesis.supporting_evidence) >= 1:
            hypothesis.status = "SUPPORTED"
        elif counter_factor >= 0.50:
            hypothesis.status = "UNSUPPORTED"
        else:
            hypothesis.status = "RESOLVED"

        return hypothesis
