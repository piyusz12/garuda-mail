"""
Phase 23 - Attack Replay Runner.
Replays attack scenarios sequentially through the detection and correlation pipeline.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Tuple
import time

from .scenarios import AttackScenario

@dataclass
class ReplayExecutionResult:
    scenario_id: str
    scenario_name: str
    total_events_replayed: int
    triggered_finding_ids: List[str]
    triggered_detection_ids: List[str]
    correlation_matches: List[str]
    elapsed_time_ms: float
    start_time: datetime
    end_time: datetime


class AttackReplayRunner:
    """Executes deterministic multi-event attack replay."""

    @classmethod
    def replay_scenario(cls, scenario: AttackScenario, detection_engine: Any) -> ReplayExecutionResult:
        base_time = datetime.now(timezone.utc) - timedelta(days=2)
        start_t = time.perf_counter()

        triggered_findings = []
        triggered_detection_ids = set()
        correlation_matches = []

        for sc_evt in scenario.events:
            simulated_ts = base_time + timedelta(seconds=sc_evt.offset_seconds)
            payload = dict(sc_evt.data)
            payload["timestamp"] = simulated_ts
            payload["event_id"] = sc_evt.event_id

            # 1. Evaluate correlation engine sequence if available
            if hasattr(detection_engine, "correlation"):
                matches = detection_engine.correlation.ingest_event(
                    asset_id=sc_evt.asset,
                    event_type=sc_evt.event_type,
                    data=payload,
                    event_id=sc_evt.event_id,
                    timestamp=simulated_ts
                )
                for m in matches:
                    correlation_matches.append(m.sequence_id)

            # 2. Evaluate detection rules
            findings = detection_engine.evaluate_event(payload, context={"counter_evidence_factor": 0.0})
            for f in findings:
                triggered_findings.append(f.finding_id)
                triggered_detection_ids.add(f.detection_id)

        elapsed_ms = (time.perf_counter() - start_t) * 1000.0

        return ReplayExecutionResult(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            total_events_replayed=len(scenario.events),
            triggered_finding_ids=triggered_findings,
            triggered_detection_ids=list(triggered_detection_ids),
            correlation_matches=list(set(correlation_matches)),
            elapsed_time_ms=round(elapsed_ms, 2),
            start_time=base_time,
            end_time=base_time + timedelta(seconds=scenario.events[-1].offset_seconds if scenario.events else 0)
        )
