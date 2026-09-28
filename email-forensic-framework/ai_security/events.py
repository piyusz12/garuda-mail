"""Garuda Enterprise AI Security - AI Security Event Bus.
Phase 30 Section 30.74: Centralized event streaming, publish-subscribe,
and audit telemetry for models, agents, prompts, RAG pipelines, and tools.
"""
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import time
import uuid


class AIEventType(str, Enum):
    # Model Events
    AI_MODEL_DISCOVERED = "AI_MODEL_DISCOVERED"
    AI_MODEL_APPROVED = "AI_MODEL_APPROVED"
    AI_MODEL_DEPLOYED = "AI_MODEL_DEPLOYED"
    AI_MODEL_CHANGED = "AI_MODEL_CHANGED"
    AI_MODEL_QUARANTINED = "AI_MODEL_QUARANTINED"
    AI_MODEL_DEPRECATED = "AI_MODEL_DEPRECATED"

    # Agent Events
    AI_AGENT_CREATED = "AI_AGENT_CREATED"
    AI_AGENT_STARTED = "AI_AGENT_STARTED"
    AI_AGENT_STOPPED = "AI_AGENT_STOPPED"
    AI_AGENT_DISABLED = "AI_AGENT_DISABLED"
    AI_AGENT_ANOMALY = "AI_AGENT_ANOMALY"

    # Prompt & Response Events
    AI_PROMPT_SCANNED = "AI_PROMPT_SCANNED"
    AI_PROMPT_BLOCKED = "AI_PROMPT_BLOCKED"
    AI_RESPONSE_SCANNED = "AI_RESPONSE_SCANNED"
    AI_RESPONSE_BLOCKED = "AI_RESPONSE_BLOCKED"

    # Tool & Retrieval Events
    AI_TOOL_INVOKED = "AI_TOOL_INVOKED"
    AI_TOOL_REVOKED = "AI_TOOL_REVOKED"
    AI_RETRIEVAL_EVENT = "AI_RETRIEVAL_EVENT"

    # DLP & Egress Events
    AI_DLP_EVALUATION = "AI_DLP_EVALUATION"
    AI_DLP_VIOLATION = "AI_DLP_VIOLATION"
    AI_EGRESS_BLOCKED = "AI_EGRESS_BLOCKED"

    # Posture & Incident Events
    AI_POSTURE_DRIFT = "AI_POSTURE_DRIFT"
    AI_ANOMALY_DETECTED = "AI_ANOMALY_DETECTED"
    AI_INCIDENT_CREATED = "AI_INCIDENT_CREATED"
    AI_POLICY_SIMULATED = "AI_POLICY_SIMULATED"


@dataclass
class AISecurityEvent:
    event_id: str
    event_type: AIEventType
    timestamp: float
    agent_id: Optional[str] = None
    model_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    event_hash: str = ""

    def __post_init__(self):
        if not self.event_hash:
            data = f"{self.event_id}:{self.event_type.value}:{self.timestamp}:{self.agent_id}:{self.model_id}:{json.dumps(self.payload, sort_keys=True)}"
            self.event_hash = hashlib.sha256(data.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "payload": self.payload,
            "event_hash": self.event_hash,
        }


class AISecurityEventBus:
    """Enterprise AI Security Event Bus with pub/sub, in-memory buffering,
    querying, and Lakehouse (Phase 22) integration."""

    _instance: Optional["AISecurityEventBus"] = None

    def __init__(self, max_buffer_size: int = 10000):
        self._events: List[AISecurityEvent] = []
        self._subscribers: Dict[str, List[Callable[[AISecurityEvent], None]]] = {}
        self._all_subscribers: List[Callable[[AISecurityEvent], None]] = []
        self._max_buffer = max_buffer_size

    @classmethod
    def get_instance(cls) -> "AISecurityEventBus":
        if cls._instance is None:
            cls._instance = AISecurityEventBus()
        return cls._instance

    def subscribe(self, event_type: Optional[AIEventType], handler: Callable[[AISecurityEvent], None]):
        """Subscribe a callback to a specific event type or all events if None."""
        if event_type is None:
            self._all_subscribers.append(handler)
        else:
            k = event_type.value
            if k not in self._subscribers:
                self._subscribers[k] = []
            self._subscribers[k].append(handler)

    def publish(
        self,
        event_type: AIEventType,
        payload: Dict[str, Any],
        agent_id: Optional[str] = None,
        model_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> AISecurityEvent:
        """Publish an event to the bus, buffer it, and notify subscribers."""
        ev = AISecurityEvent(
            event_id=f"EVT-AI-{uuid.uuid4().hex[:8].upper()}",
            event_type=event_type,
            timestamp=time.time(),
            agent_id=agent_id,
            model_id=model_id,
            user_id=user_id,
            session_id=session_id,
            payload=payload,
        )

        self._events.append(ev)
        if len(self._events) > self._max_buffer:
            self._events.pop(0)

        # Notify type-specific subscribers
        for handler in self._subscribers.get(event_type.value, []):
            try:
                handler(ev)
            except Exception:
                pass

        # Notify general subscribers
        for handler in self._all_subscribers:
            try:
                handler(ev)
            except Exception:
                pass

        return ev

    def get_events(
        self,
        event_types: Optional[List[AIEventType]] = None,
        agent_id: Optional[str] = None,
        model_id: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 100,
    ) -> List[AISecurityEvent]:
        """Query buffered events with multi-field filtering."""
        results = []
        target_types = {t.value for t in event_types} if event_types else None

        for ev in reversed(self._events):
            if target_types and ev.event_type.value not in target_types:
                continue
            if agent_id and ev.agent_id != agent_id:
                continue
            if model_id and ev.model_id != model_id:
                continue
            if start_time and ev.timestamp < start_time:
                continue
            if end_time and ev.timestamp > end_time:
                continue

            results.append(ev)
            if len(results) >= limit:
                break

        return list(reversed(results))

    def clear(self):
        """Clear buffered events (useful for unit tests)."""
        self._events.clear()

    def count(self) -> int:
        return len(self._events)
