"""
Phase 24 — Verification & Monitoring Unit Tests
Tests ConfigVerifier, TelemetryVerifier, RecoveryEngine, RemediationVerificationEngine, and ResponseWatcher.
"""

from verification.config import ConfigVerifier
from verification.telemetry import TelemetryVerifier
from verification.recovery import RecoveryEngine
from verification.engine import RemediationVerificationEngine
from monitoring.watchers import ResponseWatcher, WatcherStatus
from monitoring.recurrence import RecurrenceDetector
from connectors.registry import ConnectorRegistry


def test_config_verifier():
    connectors = ConnectorRegistry()
    res = ConfigVerifier.verify_config_state("MTA-01", connectors)
    assert res["passed"] is True
    assert res["has_legacy_tls"] is False
    assert res["has_modern_tls"] is True


def test_telemetry_verifier():
    # Pass clean sessions
    clean_sessions = [
        {"asset": "MTA-07", "tls_version": "TLS 1.3"},
        {"asset": "MTA-07", "tls_version": "TLS 1.2"},
    ]
    res_clean = TelemetryVerifier.verify_observed_telemetry("MTA-07", observed_sessions=clean_sessions)
    assert res_clean["passed"] is True
    assert res_clean["violating_sessions_count"] == 0

    # Pass legacy sessions
    dirty_sessions = [
        {"asset": "MTA-07", "tls_version": "TLS 1.0"},
    ]
    res_dirty = TelemetryVerifier.verify_observed_telemetry("MTA-07", observed_sessions=dirty_sessions)
    assert res_dirty["passed"] is False
    assert res_dirty["violating_sessions_count"] == 1


def test_recovery_engine():
    res = RecoveryEngine.evaluate_recovery_health("MTA-07")
    assert res["passed"] is True
    assert res["service_health"]["status"] == "UP"
    assert res["ready_for_monitoring"] is True


def test_multi_layer_verification_consolidated():
    connectors = ConnectorRegistry()
    report = RemediationVerificationEngine.verify_remediation("MTA-01", connectors)
    assert report.all_layers_passed is True
    assert report.verdict == "PASS"


def test_response_watcher_and_recurrence():
    watcher = ResponseWatcher()
    entry = watcher.register_watcher("INC-882", "MTA-07", "DET-TLS-001")
    assert entry.status == WatcherStatus.ACTIVE
    assert len(entry.windows) == 4

    detector = RecurrenceDetector(watcher)
    # Simulate recurring telemetry
    recurring_events = [
        {"asset": "MTA-07", "detection": "DET-TLS-001", "tls_version": "TLS 1.0"}
    ]
    matches = detector.evaluate_telemetry_batch(recurring_events)
    assert len(matches) == 1
    assert matches[0]["incident_id"] == "INC-882"
    assert entry.status == WatcherStatus.TRIGGERED_RECURRENCE
