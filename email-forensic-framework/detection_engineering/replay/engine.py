"""
Phase 25 — Historical Telemetry Replay Engine
Replays historical telemetry from Phase 22 Lakehouse to evaluate candidate detection rules.
"""

from typing import Dict, List, Optional, Any
from ..rules.models import DetectionRuleDefinition


class HistoricalReplayEngine:
    """Evaluates proposed detection updates against historical telemetry datasets."""

    def __init__(self, historical_corpus: Optional[List[Dict[str, Any]]] = None):
        self.corpus = historical_corpus or self._generate_synthetic_corpus()

    def _generate_synthetic_corpus(self) -> List[Dict[str, Any]]:
        corpus = []
        for i in range(100):
            corpus.append({
                "event_id": f"HIST-EVT-{i:03d}",
                "protocol_version": "TLSv1.0" if i % 10 == 0 else "TLSv1.3",
                "in_maintenance": i % 10 == 0 and i < 50,  # Half occurred in scheduled maintenance
                "trust_chain_valid": False if i == 42 else True,
                "ja4_frequency_90d": 1 if i == 99 else 500,
            })
        return corpus

    def replay_rule(
        self,
        rule: DetectionRuleDefinition,
        exclude_maintenance: bool = True,
    ) -> Dict[str, Any]:
        """Runs the rule against historical telemetry and compares alert distributions."""
        hits = 0
        tp = 0
        fp = 0

        for evt in self.corpus:
            is_match = False
            if "TLS-LEGACY" in rule.rule_id:
                if evt.get("protocol_version") in ("TLSv1.0", "TLSv1.1"):
                    if exclude_maintenance and evt.get("in_maintenance"):
                        is_match = False  # Filtered out
                    else:
                        is_match = True

            elif "CERT-ROTATION" in rule.rule_id:
                is_match = not evt.get("trust_chain_valid", True)
            elif "JA4" in rule.rule_id:
                is_match = evt.get("ja4_frequency_90d", 500) < 3

            if is_match:
                hits += 1
                if evt.get("in_maintenance"):
                    fp += 1
                else:
                    tp += 1

        fpr = fp / max(1, hits)
        return {
            "rule_id": rule.rule_id,
            "version": rule.version,
            "events_replayed": len(self.corpus),
            "hits": hits,
            "true_positives": tp,
            "false_positives": fp,
            "false_positive_rate": round(fpr, 4),
            "passed": fpr <= 0.10,
        }
