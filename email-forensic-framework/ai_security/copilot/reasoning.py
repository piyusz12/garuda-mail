from __future__ import annotations

from typing import Any, Dict, List


class ReasoningEngine:
    """Evidence-grounded reasoning layer that explains findings without inventing telemetry."""

    def explain(self, entity_id: str, evidence: List[Dict[str, Any]], timeline: List[Dict[str, Any]] | None = None) -> str:
        evidence_summary = ", ".join(item.get("description", "unknown factor") for item in evidence[:3])
        timeline_summary = "; ".join(item.get("description", "activity") for item in (timeline or [])[:3]) if timeline else "telemetry review"
        return (
            f"The activity involving {entity_id} is highly suspicious because the evidence indicates {evidence_summary}. "
            f"The timeline shows {timeline_summary}."
        )


__all__ = ["ReasoningEngine"]
