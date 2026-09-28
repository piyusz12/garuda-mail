"""
Data Forensic Snapshots and Evidentiary Integrity.
Components 29.36 & 29.58: Captures immutable hashed snapshots of data asset configurations and access state.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import hashlib
import json
import time
import uuid


@dataclass
class DataForensicSnapshot:
    snapshot_id: str
    asset_id: str
    asset_name: str
    classification: str
    encryption_status: Dict[str, Any]
    active_readers: List[str]
    last_volume_transferred: int
    destination_target: str
    snapshot_sha256: str = ""
    created_at: float = field(default_factory=time.time)

    def compute_hash(self) -> str:
        payload = {
            "snapshot_id": self.snapshot_id,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "classification": self.classification,
            "encryption_status": self.encryption_status,
            "active_readers": sorted(self.active_readers),
            "last_volume_transferred": self.last_volume_transferred,
            "destination_target": self.destination_target,
        }
        self.snapshot_sha256 = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        return self.snapshot_sha256

    def to_dict(self) -> Dict[str, Any]:
        if not self.snapshot_sha256:
            self.compute_hash()
        return {
            "snapshot_id": self.snapshot_id,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "classification": self.classification,
            "encryption_status": self.encryption_status,
            "active_readers": self.active_readers,
            "last_volume_transferred": self.last_volume_transferred,
            "destination_target": self.destination_target,
            "snapshot_sha256": self.snapshot_sha256,
            "created_at": self.created_at,
        }


class DataForensicsSnapshotManager:
    """Creates and stores immutable data forensic snapshots."""

    def __init__(self):
        self._snapshots: Dict[str, DataForensicSnapshot] = {}

    def capture_snapshot(
        self,
        asset_id: str,
        asset_name: str,
        classification: str,
        encryption_status: Dict[str, Any],
        active_readers: List[str],
        last_volume_transferred: int,
        destination_target: str,
    ) -> DataForensicSnapshot:
        snap = DataForensicSnapshot(
            snapshot_id=f"DSNAP-{uuid.uuid4().hex[:8].upper()}",
            asset_id=asset_id,
            asset_name=asset_name,
            classification=classification,
            encryption_status=encryption_status,
            active_readers=active_readers,
            last_volume_transferred=last_volume_transferred,
            destination_target=destination_target,
        )
        snap.compute_hash()
        self._snapshots[snap.snapshot_id] = snap
        return snap

    def get_snapshot(self, snapshot_id: str) -> Optional[DataForensicSnapshot]:
        return self._snapshots.get(snapshot_id)
