"""AI Evidence Package Compilation.
Component 30.39 & 30.89: Packages snapshots, chronological timelines, and DLP alerts into verifiable evidence cases.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import hashlib
import json
import time

from ai_security.forensics.snapshots import AIForensicSnapshot
from ai_security.forensics.timeline import AITimelineEntry


@dataclass
class AIEvidencePackage:
    case_id: str
    agent_id: str
    snapshot: AIForensicSnapshot
    timeline: List[AITimelineEntry]
    findings: List[Dict[str, Any]]
    package_sha256: str = ""
    created_at: float = field(default_factory=time.time)

    def finalize(self) -> str:
        snap_hash = self.snapshot.compute_hash()
        payload = {
            "case_id": self.case_id,
            "agent_id": self.agent_id,
            "snapshot_hash": snap_hash,
            "timeline": [t.to_dict() for t in self.timeline],
            "findings_count": len(self.findings),
        }
        self.package_sha256 = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        return self.package_sha256

    def to_dict(self) -> Dict[str, Any]:
        if not self.package_sha256:
            self.finalize()
        return {
            "case_id": self.case_id,
            "agent_id": self.agent_id,
            "snapshot": self.snapshot.to_dict(),
            "timeline": [t.to_dict() for t in self.timeline],
            "findings": self.findings,
            "package_sha256": self.package_sha256,
            "created_at": self.created_at,
        }
