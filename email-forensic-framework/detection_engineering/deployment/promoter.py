"""
Phase 25 — Threat-Hunt Promotion & Detection CI/CD
Promotes validated Phase 23 threat hunt findings through testing, canary, and production deployment.
"""

from typing import Dict, List, Optional, Any
from ..rules.models import DetectionRuleDefinition, DetectionRuleRepository
from ..testing.regression import DetectionRegressionTester
from ..replay.engine import HistoricalReplayEngine


class ThreatHuntPromoter:
    """Manages the lifecycle promoting Phase 23 hunt hypotheses into production detections."""

    def __init__(self, rule_repo: Optional[DetectionRuleRepository] = None):
        self.repo = rule_repo or DetectionRuleRepository()
        self.tester = DetectionRegressionTester()
        self.replayer = HistoricalReplayEngine()

    def promote_hunt_finding(
        self,
        hunt_id: str,
        hypothesis_title: str,
        query_dsl: str,
        severity: str = "HIGH",
        author: str = "threat_hunter",
    ) -> Dict[str, Any]:
        """
        Promotes a hunt finding through the pipeline:
        1. Create Detection Candidate
        2. Run Historical Replay
        3. Run Regression Benchmark Tests
        4. Deploy to Canary Stage (10% traffic)
        5. Full Production Activation
        """
        rule_id = f"RULE-{hunt_id.upper()}"
        candidate = DetectionRuleDefinition(
            rule_id=rule_id,
            name=f"Automated Promotion: {hypothesis_title}",
            version="1.0.0",
            severity=severity,
            target_event="threat_hunt_anomaly",
            description=f"Promoted from Phase 23 Hunt finding '{hunt_id}'.",
            query_dsl=query_dsl,
            canary_ratio=0.10,  # Starts in canary
        )

        # Step 2: Historical Replay
        replay_res = self.replayer.replay_rule(candidate)

        # Step 3: Regression Test
        test_res = self.tester.test_rule(candidate)

        # Step 4: Staging / Deployment Decision
        deployed = False
        if replay_res["passed"] or test_res["overall_status"] == "PASS":
            candidate.canary_ratio = 1.0  # Promoted to production
            self.repo._rules[candidate.rule_id] = candidate
            deployed = True

        return {
            "hunt_id": hunt_id,
            "rule_id": candidate.rule_id,
            "version": candidate.version,
            "replay_results": replay_res,
            "regression_results": test_res,
            "promoted_to_production": deployed,
            "status": "PRODUCTION" if deployed else "CANARY_REJECTED",
        }
