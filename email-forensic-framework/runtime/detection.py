"""
Container and Workload Runtime Detection Engine.
Component 25 & 45: Real-time detection of reverse shells, cryptominers, unauthorized binaries, and egress.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import re
import uuid

from runtime.telemetry import RuntimeEvent, RuntimeEventType
from runtime.baselines import RuntimeBaselineManager


class FindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RuntimeFinding:
    finding_id: str
    workload_id: str
    container_id: str
    severity: FindingSeverity
    category: str
    title: str
    description: str
    evidence: Dict[str, Any]
    mitre_tactics: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "workload_id": self.workload_id,
            "container_id": self.container_id,
            "severity": self.severity.value if isinstance(self.severity, FindingSeverity) else self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "mitre_tactics": self.mitre_tactics,
            "timestamp": self.timestamp,
        }


class ContainerRuntimeDetector:
    """Detects runtime anomalies, reverse shells, miners, and policy violations."""

    def __init__(self, baseline_manager: Optional[RuntimeBaselineManager] = None):
        self.baseline_manager = baseline_manager or RuntimeBaselineManager()
        self.findings: List[RuntimeFinding] = []

        # Known threat patterns
        self.reverse_shell_patterns = [
            r"nc\s+.*-e",
            r"bash\s+-i",
            r"/bin/(ba)?sh\s+-i",
            r"python.*pty\.spawn",
            r"socat\s+exec",
            r"perl\s+-e.*socket",
        ]
        self.miner_signatures = {"xmrig", "stratum+tcp", "minerd", "cryptonight", "monero"}

    def inspect_event(self, event: RuntimeEvent) -> List[RuntimeFinding]:
        """Analyze a runtime event and generate findings if threats/deviations exist."""
        new_findings: List[RuntimeFinding] = []

        # 1. Reverse shell detection
        if event.cmdline:
            for pattern in self.reverse_shell_patterns:
                if re.search(pattern, event.cmdline, re.IGNORECASE):
                    finding = RuntimeFinding(
                        finding_id=f"RFIND-{uuid.uuid4().hex[:8].upper()}",
                        workload_id=event.workload_id,
                        container_id=event.container_id,
                        severity=FindingSeverity.CRITICAL,
                        category="REVERSE_SHELL",
                        title=f"Interactive Reverse Shell detected in {event.workload_id}",
                        description=f"Commandline execution matching reverse shell pattern: {event.cmdline}",
                        evidence={"cmdline": event.cmdline, "process": event.process_name, "uid": event.uid},
                        mitre_tactics=["Execution (T1059)", "Command and Control (T1071)"],
                    )
                    new_findings.append(finding)

        # 2. Cryptomining signature detection
        if event.cmdline or event.process_name:
            target_str = f"{event.process_name or ''} {event.cmdline or ''}".lower()
            if any(miner in target_str for miner in self.miner_signatures):
                finding = RuntimeFinding(
                    finding_id=f"RFIND-{uuid.uuid4().hex[:8].upper()}",
                    workload_id=event.workload_id,
                    container_id=event.container_id,
                    severity=FindingSeverity.CRITICAL,
                    category="CRYPTOMINER",
                    title=f"Cryptocurrency miner detected in {event.workload_id}",
                    description=f"Process or commandline contains cryptomining signature: {target_str}",
                    evidence={"process": event.process_name, "cmdline": event.cmdline},
                    mitre_tactics=["Impact (T1496 - Resource Hijacking)"],
                )
                new_findings.append(finding)

        # 3. Privilege escalation detection (root execution when non-root expected)
        if event.uid == 0:
            baseline = self.baseline_manager.get_baseline(event.workload_id)
            if baseline and 0 not in baseline.allowed_uids:
                finding = RuntimeFinding(
                    finding_id=f"RFIND-{uuid.uuid4().hex[:8].upper()}",
                    workload_id=event.workload_id,
                    container_id=event.container_id,
                    severity=FindingSeverity.HIGH,
                    category="PRIVILEGE_ESCALATION",
                    title=f"Unexpected Root UID Execution in {event.workload_id}",
                    description=f"Process {event.process_name} executed as root (UID 0), violating container least-privilege policy.",
                    evidence={"process": event.process_name, "uid": event.uid, "allowed_uids": list(baseline.allowed_uids)},
                    mitre_tactics=["Privilege Escalation (T1548)"],
                )
                new_findings.append(finding)

        # 4. Sensitive filesystem modifications
        if event.event_type == RuntimeEventType.FILE_MODIFIED and event.file_path:
            sensitive_paths = ["/etc/shadow", "/etc/passwd", "/root/.ssh", "/var/run/secrets/kubernetes.io/serviceaccount"]
            if any(sp in event.file_path for sp in sensitive_paths):
                finding = RuntimeFinding(
                    finding_id=f"RFIND-{uuid.uuid4().hex[:8].upper()}",
                    workload_id=event.workload_id,
                    container_id=event.container_id,
                    severity=FindingSeverity.CRITICAL,
                    category="SENSITIVE_FILE_TAMPERING",
                    title=f"Sensitive Container File Tampering in {event.workload_id}",
                    description=f"Modification of sensitive system path: {event.file_path}",
                    evidence={"file_path": event.file_path, "process": event.process_name, "uid": event.uid},
                    mitre_tactics=["Defense Evasion (T1070)", "Credential Access (T1552)"],
                )
                new_findings.append(finding)

        # 5. Baseline Deviations (Process, Outbound port, Destination IP)
        deviations = self.baseline_manager.evaluate_event(event)
        for dev in deviations:
            # Skip if already flagged above
            if "unapproved_process" in dev:
                new_findings.append(
                    RuntimeFinding(
                        finding_id=f"RFIND-{uuid.uuid4().hex[:8].upper()}",
                        workload_id=event.workload_id,
                        container_id=event.container_id,
                        severity=FindingSeverity.HIGH,
                        category="UNAPPROVED_BINARY",
                        title=f"Unapproved Binary Execution in {event.workload_id}",
                        description=f"Deviation detected: {dev}",
                        evidence={"deviation": dev, "event": event.to_dict()},
                        mitre_tactics=["Execution (T1204)"],
                    )
                )
            elif "unapproved_destination" in dev or "unapproved_outbound_port" in dev:
                new_findings.append(
                    RuntimeFinding(
                        finding_id=f"RFIND-{uuid.uuid4().hex[:8].upper()}",
                        workload_id=event.workload_id,
                        container_id=event.container_id,
                        severity=FindingSeverity.HIGH,
                        category="ANOMALOUS_EGRESS",
                        title=f"Anomalous Outbound Connection in {event.workload_id}",
                        description=f"Deviation detected: {dev}",
                        evidence={"deviation": dev, "destination_ip": event.destination_ip, "port": event.destination_port},
                        mitre_tactics=["Command and Control (T1071)", "Exfiltration (T1041)"],
                    )
                )

        self.findings.extend(new_findings)
        return new_findings

    def get_all_findings(self) -> List[RuntimeFinding]:
        return list(self.findings)

    def get_findings_for_workload(self, workload_id: str) -> List[RuntimeFinding]:
        return [f for f in self.findings if f.workload_id == workload_id]
