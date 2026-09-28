"""Garuda Enterprise AI Security - Threat Hunting Engine.
Phase 30 Section 30.82: Execution engine for AI threat hunts.
"""
from typing import Dict, List, Optional, Any
from ai_security.events import AISecurityEvent, AISecurityEventBus
from ai_security.hunting.queries import (
    AIHuntQuery,
    AIHuntFinding,
    SensitiveAccessExternalToolHunt,
    ModelArtifactHashTamperHunt,
    ToolCallRateAnomalyHunt,
    CrossScopeRAGRetrievalHunt,
)


class AIHuntEngine:
    """Orchestrates and executes proactive AI threat hunting queries across the event stream."""

    def __init__(self, event_bus: Optional[AISecurityEventBus] = None):
        self.event_bus = event_bus or AISecurityEventBus.get_instance()
        self._registered_hunts: Dict[str, AIHuntQuery] = {}
        self.register_default_hunts()

    def register_default_hunts(self):
        self.register_hunt(SensitiveAccessExternalToolHunt())
        self.register_hunt(ModelArtifactHashTamperHunt())
        self.register_hunt(ToolCallRateAnomalyHunt())
        self.register_hunt(CrossScopeRAGRetrievalHunt())

    def register_hunt(self, hunt: AIHuntQuery):
        self._registered_hunts[hunt.hunt_id] = hunt

    def get_hunt(self, hunt_id: str) -> Optional[AIHuntQuery]:
        return self._registered_hunts.get(hunt_id)

    def list_hunts(self) -> List[AIHuntQuery]:
        return list(self._registered_hunts.values())

    def run_hunt(
        self,
        hunt_id: str,
        events: Optional[List[AISecurityEvent]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[AIHuntFinding]:
        hunt = self._registered_hunts.get(hunt_id)
        if not hunt:
            raise KeyError(f"Hunt '{hunt_id}' not found.")
        target_events = events if events is not None else self.event_bus.get_events(limit=5000)
        return hunt.execute(target_events, context)

    def run_all_hunts(
        self,
        events: Optional[List[AISecurityEvent]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, List[AIHuntFinding]]:
        target_events = events if events is not None else self.event_bus.get_events(limit=5000)
        results = {}
        for hunt_id, hunt in self._registered_hunts.items():
            findings = hunt.execute(target_events, context)
            if findings:
                results[hunt_id] = findings
        return results
