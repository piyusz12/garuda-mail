"""
Phase 25 — Case Evidence Packaging
Packages alerts, timeline, findings, actions, approvals, verification, and reports
into an auditable, cryptographically sealed evidence package.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import hashlib
import json
import time


class EvidencePackager:
    """Creates a sealed evidence package with SHA-256 integrity manifest."""

    @staticmethod
    def create_package(
        case_id: str,
        alerts: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        actions: List[Dict[str, Any]],
        approvals: List[Dict[str, Any]],
        verification: Dict[str, Any],
        report: Dict[str, Any],
        graph: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Assembles and hashes evidence artifacts into a unified package."""
        timestamp = time.time()
        iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

        files: Dict[str, str] = {
            "alerts.json": json.dumps(alerts, indent=2, sort_keys=True, default=str),
            "timeline.json": json.dumps(timeline, indent=2, sort_keys=True, default=str),
            "findings.json": json.dumps(findings, indent=2, sort_keys=True, default=str),
            "actions.json": json.dumps(actions, indent=2, sort_keys=True, default=str),
            "approvals.json": json.dumps(approvals, indent=2, sort_keys=True, default=str),
            "verification.json": json.dumps(verification, indent=2, sort_keys=True, default=str),
            "final_report.json": json.dumps(report, indent=2, sort_keys=True, default=str),
            "graph.json": json.dumps(graph or {}, indent=2, sort_keys=True, default=str),
        }

        # Calculate per-file hashes
        manifest_files: Dict[str, str] = {}
        for filename, content in files.items():
            manifest_files[filename] = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Overall package root hash
        manifest_raw = json.dumps(manifest_files, sort_keys=True)
        root_package_hash = hashlib.sha256(manifest_raw.encode("utf-8")).hexdigest()

        manifest = {
            "case_id": case_id,
            "created_at": timestamp,
            "iso_time": iso,
            "package_hash": root_package_hash,
            "files": manifest_files,
            "file_count": len(files),
        }

        return {
            "case_id": case_id,
            "manifest": manifest,
            "artifacts": files,
            "sealed": True,
        }
