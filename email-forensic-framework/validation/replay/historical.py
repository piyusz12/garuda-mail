"""
Historical Telemetry Replay Engine.
Replays stored telemetry (e.g. from Phase 22 Lakehouse) through detectors to find regressions or false positives.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class HistoricalReplayResult:
    replay_id: str
    rule_id: str
    total_events_evaluated: int
    true_positive_triggers: int
    false_positive_triggers: int
    execution_time_seconds: float
    is_regression_free: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "replay_id": self.replay_id,
            "rule_id": self.rule_id,
            "total_events_evaluated": self.total_events_evaluated,
            "true_positive_triggers": self.true_positive_triggers,
            "false_positive_triggers": self.false_positive_triggers,
            "execution_time_seconds": round(self.execution_time_seconds, 3),
            "is_regression_free": self.is_regression_free,
        }


class HistoricalValidationReplay:
    """Replays historical telemetry windows to validate detection behavior."""

    @staticmethod
    def replay_corpus(rule_id: str, events: List[Dict[str, Any]]) -> HistoricalReplayResult:
        t0 = time.time()
        tp = 0
        fp = 0

        for ev in events:
            # Check if event matches rule criteria
            ev_type = ev.get("event_type", "")
            is_malicious = ev.get("label") == "POSITIVE"

            # Match logic
            fired = False
            if "TLS" in rule_id and ev.get("tls_version") in ("TLS 1.0", "TLS 1.1"):
                fired = True
            elif "CERT" in rule_id and (ev.get("is_self_signed") or ev.get("chain_valid") is False):
                fired = True

            if fired:
                if is_malicious:
                    tp += 1
                else:
                    fp += 1

        t_dur = time.time() - t0
        return HistoricalReplayResult(
            replay_id=f"REPLAY-{int(time.time() * 1000)}",
            rule_id=rule_id,
            total_events_evaluated=len(events),
            true_positive_triggers=tp,
            false_positive_triggers=fp,
            execution_time_seconds=t_dur,
            is_regression_free=(fp == 0),
        )
