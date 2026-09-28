"""AI Forensic Snapshots and Evidentiary Integrity.
Components 30.39, 30.53, 30.89: Captures immutable SHA-256 hashed forensic snapshots of agent and inference states.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import hashlib
import json
import time
import uuid


@dataclass
class AIForensicSnapshot:
    snapshot_id: str
    agent_id: str
    model_id: str
    identity_id: str
    prompt_hash: str
    retrieved_documents: List[str]
    tool_calls: List[str]
    dlp_action: str
    destination_target: str
    snapshot_sha256: str = ""
    created_at: float = field(default_factory=time.time)

    def compute_hash(self) -> str:
        payload = {
            "snapshot_id": self.snapshot_id,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "identity_id": self.identity_id,
            "prompt_hash": self.prompt_hash,
            "retrieved_documents": sorted(self.retrieved_documents),
            "tool_calls": sorted(self.tool_calls),
            "dlp_action": self.dlp_action,
            "destination_target": self.destination_target,
        }
        self.snapshot_sha256 = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        return self.snapshot_sha256

    def to_dict(self) -> Dict[str, Any]:
        if not self.snapshot_sha256:
            self.compute_hash()
        return {
            "snapshot_id": self.snapshot_id,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "identity_id": self.identity_id,
            "prompt_hash": self.prompt_hash,
            "retrieved_documents": self.retrieved_documents,
            "tool_calls": self.tool_calls,
            "dlp_action": self.dlp_action,
            "destination_target": self.destination_target,
            "snapshot_sha256": self.snapshot_sha256,
            "created_at": self.created_at,
        }


class AIForensicSnapshotManager:
    """Creates and stores immutable data and execution snapshots for AI incident response."""

    def __init__(self):
        self._snapshots: Dict[str, AIForensicSnapshot] = {}

    def capture_snapshot(
        self,
        agent_id: str,
        model_id: str,
        identity_id: str,
        prompt_hash: str,
        retrieved_documents: List[str],
        tool_calls: List[str],
        dlp_action: str,
        destination_target: str,
    ) -> AIForensicSnapshot:
        snap = AIForensicSnapshot(
            snapshot_id=f"AISNAP-{uuid.uuid4().hex[:8].upper()}",
            agent_id=agent_id,
            model_id=model_id,
            identity_id=identity_id,
            prompt_hash=prompt_hash,
            retrieved_documents=retrieved_documents,
            tool_calls=tool_calls,
            dlp_action=dlp_action,
            destination_target=destination_target,
        )
        snap.compute_hash()
        self._snapshots[snap.snapshot_id] = snap
        return snap

    def save_snapshot(self, snapshot: AIForensicSnapshot) -> None:
        snapshot.compute_hash()
        self._snapshots[snapshot.snapshot_id] = snapshot

    def get_snapshot(self, snapshot_id: str) -> Optional[AIForensicSnapshot]:
        return self._snapshots.get(snapshot_id)
