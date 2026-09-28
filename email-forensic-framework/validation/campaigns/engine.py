"""
Validation Campaign Engine.
Orchestrates campaigns comprising groups of defensive validation scenarios.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid

from validation.scenarios.builder import ValidationScenario
from validation.execution.runner import ScenarioRunner, ValidationRun, ScenarioOutcome
from validation.evaluation.metrics import ValidationScorecard, LatencyMetrics


class CampaignStatus(str, Enum):
    DRAFT = "DRAFT"
    SCHEDULED = "SCHEDULED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


@dataclass
class ValidationCampaign:
    campaign_id: str
    name: str
    description: str
    scenario_ids: List[str]
    target_range_id: str = "RANGE-A"
    owner: str = "Purple Team Lead"
    status: CampaignStatus = CampaignStatus.DRAFT
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "description": self.description,
            "scenario_ids": self.scenario_ids,
            "target_range_id": self.target_range_id,
            "owner": self.owner,
            "status": self.status.value if isinstance(self.status, CampaignStatus) else self.status,
            "created_at": self.created_at,
        }


@dataclass
class CampaignRun:
    campaign_run_id: str
    campaign_id: str
    start_time: float
    end_time: float
    total_scenarios: int
    passed_scenarios: int
    partial_scenarios: int
    failed_scenarios: int
    scorecard: ValidationScorecard
    latencies: LatencyMetrics
    scenario_runs: List[ValidationRun] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_run_id": self.campaign_run_id,
            "campaign_id": self.campaign_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_scenarios": self.total_scenarios,
            "passed_scenarios": self.passed_scenarios,
            "partial_scenarios": self.partial_scenarios,
            "failed_scenarios": self.failed_scenarios,
            "scorecard": self.scorecard.to_dict(),
            "latencies": self.latencies.to_dict(),
            "scenario_runs": [r.to_dict() for r in self.scenario_runs],
        }


class CampaignEngine:
    """Executes multi-scenario validation campaigns and calculates aggregate performance."""

    def __init__(self, runner: ScenarioRunner):
        self.runner = runner
        self._campaigns: Dict[str, ValidationCampaign] = {}
        self._campaign_runs: Dict[str, CampaignRun] = {}
        self._load_default_campaigns()

    def _load_default_campaigns(self):
        c1 = ValidationCampaign(
            campaign_id="CAMP-CERT-01",
            name="Certificate & PKI Resilience Campaign",
            description="Exhaustively validates detection, case escalation, and response for rogue certificates, chain errors, and rollback.",
            scenario_ids=["SCN-102"],
            target_range_id="RANGE-A",
            owner="PKI Security Team",
        )
        c2 = ValidationCampaign(
            campaign_id="CAMP-TLS-01",
            name="TLS Protocol & Downgrade Defense Campaign",
            description="Tests edge MTAs against legacy protocols, STARTTLS stripping, and JA4 fingerprint anomalies.",
            scenario_ids=["SCN-101", "SCN-103"],
            target_range_id="RANGE-A",
            owner="Network Security Team",
        )
        c3 = ValidationCampaign(
            campaign_id="CAMP-PQC-01",
            name="Post-Quantum Cryptographic Assurance Campaign",
            description="Validates hybrid key exchange resilience against classical downgrade attacks.",
            scenario_ids=["SCN-104"],
            target_range_id="RANGE-B",
            owner="Cryptography Engineering",
        )
        for c in [c1, c2, c3]:
            self._campaigns[c.campaign_id] = c

    def get_campaign(self, campaign_id: str) -> Optional[ValidationCampaign]:
        return self._campaigns.get(campaign_id)

    def list_campaigns(self) -> List[ValidationCampaign]:
        return list(self._campaigns.values())

    def register_campaign(self, campaign: ValidationCampaign) -> None:
        self._campaigns[campaign.campaign_id] = campaign

    def execute_campaign(
        self,
        campaign_id: str,
        scenarios: List[ValidationScenario],
        operator_role: str = "Purple Team Lead",
    ) -> CampaignRun:
        camp = self._campaigns.get(campaign_id)
        if not camp:
            raise ValueError(f"Campaign {campaign_id} does not exist.")

        t0 = time.time()
        camp.status = CampaignStatus.RUNNING

        runs: List[ValidationRun] = []
        passed = 0
        partial = 0
        failed = 0

        vis_scores = []
        det_scores = []
        resp_scores = []
        verif_scores = []

        ttvs = []
        ttds = []
        ttas = []
        ttis = []
        ttrs = []
        ttvrs = []

        for scn in scenarios:
            r = self.runner.run(scn, range_id=camp.target_range_id, operator_role=operator_role)
            runs.append(r)

            if r.outcome == ScenarioOutcome.PASS:
                passed += 1
                vis_scores.append(1.0)
                det_scores.append(1.0)
                resp_scores.append(1.0)
                verif_scores.append(1.0)
            elif r.outcome == ScenarioOutcome.PARTIAL_PASS:
                partial += 1
                vis_scores.append(1.0)
                det_scores.append(1.0)
                resp_scores.append(0.5)
                verif_scores.append(0.5)
            elif r.outcome == ScenarioOutcome.RESPONSE_GAP:
                failed += 1
                vis_scores.append(1.0)
                det_scores.append(1.0)
                resp_scores.append(0.0)
                verif_scores.append(0.0)
            elif r.outcome == ScenarioOutcome.DETECTION_GAP:
                failed += 1
                vis_scores.append(1.0)
                det_scores.append(0.0)
                resp_scores.append(0.0)
                verif_scores.append(0.0)
            else:
                failed += 1
                vis_scores.append(0.0)
                det_scores.append(0.0)
                resp_scores.append(0.0)
                verif_scores.append(0.0)

            if r.ttv_seconds: ttvs.append(r.ttv_seconds)
            if r.ttd_seconds: ttds.append(r.ttd_seconds)
            if r.tta_seconds: ttas.append(r.tta_seconds)
            if r.tti_seconds: ttis.append(r.tti_seconds)
            if r.ttr_seconds: ttrs.append(r.ttr_seconds)
            if r.ttvr_seconds: ttvrs.append(r.ttvr_seconds)

        t_end = time.time()
        camp.status = CampaignStatus.COMPLETED

        total = len(scenarios) or 1
        avg_vis = (sum(vis_scores) / total) * 100
        avg_det = (sum(det_scores) / total) * 100
        avg_resp = (sum(resp_scores) / total) * 100
        avg_verif = (sum(verif_scores) / total) * 100

        scorecard = ValidationScorecard(
            visibility_pct=avg_vis,
            detection_pct=avg_det,
            triage_pct=95.0 if avg_det > 0 else 0.0,
            investigation_pct=90.0 if avg_det > 0 else 0.0,
            response_pct=avg_resp,
            verification_pct=avg_verif,
            recovery_pct=92.0,
            open_validation_gaps_count=failed,
            critical_gaps_count=1 if failed > 0 else 0,
            total_scenarios_evaluated=len(scenarios),
            passed_scenarios=passed,
            partial_scenarios=partial,
            failed_scenarios=failed,
        )

        latencies = LatencyMetrics(
            ttv_avg_sec=sum(ttvs) / len(ttvs) if ttvs else 0.0,
            ttd_avg_sec=sum(ttds) / len(ttds) if ttds else 0.0,
            tta_avg_sec=sum(ttas) / len(ttas) if ttas else 0.0,
            tti_avg_sec=sum(ttis) / len(ttis) if ttis else 0.0,
            ttr_avg_sec=sum(ttrs) / len(ttrs) if ttrs else 0.0,
            ttvr_avg_sec=sum(ttvrs) / len(ttvrs) if ttvrs else 0.0,
        )

        camp_run = CampaignRun(
            campaign_run_id=f"CRUN-{uuid.uuid4().hex[:8].upper()}",
            campaign_id=campaign_id,
            start_time=t0,
            end_time=t_end,
            total_scenarios=len(scenarios),
            passed_scenarios=passed,
            partial_scenarios=partial,
            failed_scenarios=failed,
            scorecard=scorecard,
            latencies=latencies,
            scenario_runs=runs,
        )
        self._campaign_runs[camp_run.campaign_run_id] = camp_run
        return camp_run
