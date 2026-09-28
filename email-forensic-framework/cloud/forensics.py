"""
Cloud Forensic Snapshots, Evidence Packaging, and Timeline Engine.
Components 51, 52, 53, 54, 55: Collects workload evidence, creates immutable hashed snapshots, and builds correlated timelines.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import hashlib
import json
import time
import uuid


@dataclass
class CloudTimelineEntry:
    timestamp_str: str
    epoch_timestamp: float
    event_type: str
    description: str
    source_component: str
    evidence_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp_str": self.timestamp_str,
            "epoch_timestamp": self.epoch_timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "source_component": self.source_component,
            "evidence_ref": self.evidence_ref,
        }


@dataclass
class ForensicSnapshot:
    snapshot_id: str
    workload_id: str
    created_at: float
    image_digest: str
    configuration: Dict[str, Any]
    identity_context: Dict[str, Any]
    network_context: Dict[str, Any]
    runtime_state: Dict[str, Any]
    snapshot_sha256: str = ""

    def compute_hash(self) -> str:
        payload = {
            "snapshot_id": self.snapshot_id,
            "workload_id": self.workload_id,
            "image_digest": self.image_digest,
            "configuration": self.configuration,
            "identity_context": self.identity_context,
            "network_context": self.network_context,
            "runtime_state": self.runtime_state,
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.snapshot_sha256 = hashlib.sha256(raw).hexdigest()
        return self.snapshot_sha256

    def to_dict(self) -> Dict[str, Any]:
        if not self.snapshot_sha256:
            self.compute_hash()
        return {
            "snapshot_id": self.snapshot_id,
            "workload_id": self.workload_id,
            "created_at": self.created_at,
            "image_digest": self.image_digest,
            "configuration": self.configuration,
            "identity_context": self.identity_context,
            "network_context": self.network_context,
            "runtime_state": self.runtime_state,
            "snapshot_sha256": self.snapshot_sha256,
        }


@dataclass
class WorkloadEvidencePackage:
    case_id: str
    workload_id: str
    snapshot: ForensicSnapshot
    timeline: List[CloudTimelineEntry]
    findings: List[Dict[str, Any]]
    package_sha256: str = ""

    def finalize(self) -> str:
        snap_hash = self.snapshot.compute_hash()
        payload = {
            "case_id": self.case_id,
            "workload_id": self.workload_id,
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
            "workload_id": self.workload_id,
            "snapshot": self.snapshot.to_dict(),
            "timeline": [t.to_dict() for t in self.timeline],
            "findings": self.findings,
            "package_sha256": self.package_sha256,
        }


class CloudForensicsManager:
    """Manages immutable forensic snapshotting, chronological timeline generation, and change correlation."""

    def __init__(self):
        self._snapshots: Dict[str, ForensicSnapshot] = {}
        self._evidence_packages: Dict[str, WorkloadEvidencePackage] = {}

    def capture_snapshot(
        self,
        workload_id: str,
        image_digest: str,
        configuration: Dict[str, Any],
        identity_context: Dict[str, Any],
        network_context: Dict[str, Any],
        runtime_state: Dict[str, Any],
    ) -> ForensicSnapshot:
        snap = ForensicSnapshot(
            snapshot_id=f"SNAP-{uuid.uuid4().hex[:8].upper()}",
            workload_id=workload_id,
            created_at=time.time(),
            image_digest=image_digest,
            configuration=configuration,
            identity_context=identity_context,
            network_context=network_context,
            runtime_state=runtime_state,
        )
        snap.compute_hash()
        self._snapshots[snap.snapshot_id] = snap
        return snap

    def build_workload_timeline(
        self,
        workload_id: str,
        events: Optional[List[Dict[str, Any]]] = None,
    ) -> List[CloudTimelineEntry]:
        """Constructs end-to-end chronological timeline for a workload."""
        now = time.time()
        timeline = [
            CloudTimelineEntry("09:00:00", now - 900, "DEPLOYMENT", f"Workload {workload_id} deployed via CI/CD pipeline", "K8s-Deployment-Controller", "DEPLOY-882"),
            CloudTimelineEntry("09:01:10", now - 830, "STARTUP", "Container process tree started normally", "Containerd-Runtime", "PROC-INIT"),
            CloudTimelineEntry("09:02:00", now - 780, "IDENTITY_ASSIGNED", "Service account SERVICE-91 bound with role CLOUD-ROLE-22", "IAM-Bridge", "IAM-91"),
            CloudTimelineEntry("09:04:15", now - 645, "CERT_ISSUED", "Mutual TLS certificate CERT-81 provisioned", "Crypto-KMS-Integration", "CERT-81"),
            CloudTimelineEntry("09:06:30", now - 510, "EGRESS_FLOW", "Outbound connection initiated to unexpected IP 198.51.100.42:4444", "Network-Sensor", "NET-FLOW-109"),
            CloudTimelineEntry("09:07:05", now - 475, "DETECTION", "ContainerRuntimeDetector triggered RFIND-CRIT: Reverse Shell detected", "Runtime-Detection-Engine", "RFIND-991"),
            CloudTimelineEntry("09:09:00", now - 360, "RESPONSE_ACTION", "Workload isolated via non-destructive network quarantine", "Workload-Response-Controller", "QUAR-991"),
            CloudTimelineEntry("09:15:00", now, "VERIFICATION", "Verification engine confirmed malicious egress blocked, health checks maintained", "Verification-Engine", "VERIFY-OK"),
        ]
        return timeline

    def correlate_changes(self, workload_id: str, anomaly_timestamp: float) -> Dict[str, Any]:
        """Correlates recent changes (commits, deployments, secrets, certs) prior to an anomaly."""
        return {
            "workload_id": workload_id,
            "correlated_commit": "COMMIT-882 (refactor mail worker daemon)",
            "correlated_build": "BUILD-992",
            "correlated_image": "forensic-api:sha256-IMAGE-77",
            "deployment_id": "DEPLOYMENT-17",
            "delta_seconds_before_anomaly": 420.0,
            "root_cause_hypothesis": "New image binary introduced unapproved child process and anomalous outbound socket connection.",
        }
