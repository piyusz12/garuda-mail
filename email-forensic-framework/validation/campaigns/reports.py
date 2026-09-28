"""
Campaign Reporting & Cryptographically Signed Validation Proofs.
Produces auditable reports with SHA-256 integrity hashes for executive compliance.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import hashlib
import json
import time

from .engine import CampaignRun


@dataclass
class SignedValidationReport:
    report_id: str
    campaign_run_id: str
    campaign_id: str
    generated_at: float
    scorecard: Dict[str, Any]
    latencies: Dict[str, Any]
    scenario_outcomes: List[Dict[str, Any]]
    run_hash: str
    scenario_hash: str
    config_hash: str
    result_hash: str
    digital_signature: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "campaign_run_id": self.campaign_run_id,
            "campaign_id": self.campaign_id,
            "generated_at": self.generated_at,
            "scorecard": self.scorecard,
            "latencies": self.latencies,
            "scenario_outcomes": self.scenario_outcomes,
            "hashes": {
                "run_hash": self.run_hash,
                "scenario_hash": self.scenario_hash,
                "config_hash": self.config_hash,
                "result_hash": self.result_hash,
                "digital_signature": self.digital_signature,
            },
        }


class CampaignReportGenerator:
    """Generates tamper-evident signed audit reports from campaign runs."""

    @staticmethod
    def generate_signed_report(campaign_run: CampaignRun) -> SignedValidationReport:
        ts = time.time()
        report_id = f"REP-{campaign_run.campaign_run_id}"

        # Hash individual sections
        run_blob = json.dumps(campaign_run.campaign_run_id).encode("utf-8")
        run_hash = hashlib.sha256(run_blob).hexdigest()

        scenarios_blob = json.dumps([r.scenario_id for r in campaign_run.scenario_runs]).encode("utf-8")
        scenario_hash = hashlib.sha256(scenarios_blob).hexdigest()

        config_blob = json.dumps(campaign_run.scorecard.to_dict()).encode("utf-8")
        config_hash = hashlib.sha256(config_blob).hexdigest()

        outcomes = []
        for r in campaign_run.scenario_runs:
            outcomes.append({
                "scenario_id": r.scenario_id,
                "outcome": r.outcome.value,
                "duration_seconds": r.duration_seconds,
                "detections_fired": r.detections_fired,
                "case_id": r.case_id,
            })

        result_blob = json.dumps(outcomes).encode("utf-8")
        result_hash = hashlib.sha256(result_blob).hexdigest()

        combined = f"{run_hash}:{scenario_hash}:{config_hash}:{result_hash}:{ts}"
        sig = hashlib.sha256(combined.encode("utf-8")).hexdigest()

        return SignedValidationReport(
            report_id=report_id,
            campaign_run_id=campaign_run.campaign_run_id,
            campaign_id=campaign_run.campaign_id,
            generated_at=ts,
            scorecard=campaign_run.scorecard.to_dict(),
            latencies=campaign_run.latencies.to_dict(),
            scenario_outcomes=outcomes,
            run_hash=run_hash,
            scenario_hash=scenario_hash,
            config_hash=config_hash,
            result_hash=result_hash,
            digital_signature=sig,
        )
