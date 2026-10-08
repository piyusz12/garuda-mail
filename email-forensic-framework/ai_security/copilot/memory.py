from __future__ import annotations

from typing import Any, Dict, List


class CopilotMemory:
    """Store analyst investigations and conclusions for follow-up queries."""

    def __init__(self):
        self._investigations: Dict[str, Dict[str, Any]] = {}

    def save(self, investigation: Dict[str, Any]) -> Dict[str, Any]:
        investigation_id = investigation.get("investigation_id", "INV-UNKNOWN")
        self._investigations[investigation_id] = investigation
        return investigation

    def get(self, investigation_id: str) -> Dict[str, Any] | None:
        return self._investigations.get(investigation_id)

    def list(self) -> List[Dict[str, Any]]:
        return list(self._investigations.values())

    def append_feedback(self, investigation_id: str, label: str, comment: str = "") -> Dict[str, Any]:
        entry = self._investigations.setdefault(investigation_id, {})
        entry["feedback"] = {"label": label, "comment": comment}
        return entry


__all__ = ["CopilotMemory"]
