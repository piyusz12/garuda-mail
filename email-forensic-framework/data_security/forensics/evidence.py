"""
Data Security Evidence Packaging.
Components 29.35 & 29.36: Packages data forensic snapshots, timelines, and DLP findings into verifiable cases.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import hashlib
import json
import time

from data_security.forensics.snapshots import DataForensicSnapshot
from data_security.forensics.timeline import DataTimelineEntry


@dataclass
class DataEvidencePackage:
    case_id: str
    asset_id: str
    snapshot: DataForensicSnapshot
    timeline: List[DataTimelineEntry]
    findings: List[Dict[str, Any]]
    package_sha256: str = ""
    created_at: float = field(default_factory=time.time)

    def finalize(self) -> str:
        snap_hash = self.snapshot.compute_hash()
        payload = {
            "case_id": self.case_id,
            "asset_id": self.asset_id,
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
            "asset_id": self.asset_id,
            "snapshot": self.snapshot.to_dict(),
            "timeline": [t.to_dict() for t in self.timeline],
            "findings": self.findings,
            "package_sha256": self.package_sha256,
            "created_at": self.created_at,
        }
