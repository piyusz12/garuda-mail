"""Tests for Cyber Range, Environments, Isolation Boundaries, and Teardown."""
import pytest
from validation.range import (
    RangeManager,
    IsolationController,
    RangeIsolationViolation,
    RangeStatus,
    IsolationLevel,
)


def test_cyber_range_manager():
    mgr = RangeManager()
    ranges = mgr.list_ranges()
    assert len(ranges) >= 3

    range_a = mgr.get_range("RANGE-A")
    assert range_a is not None
    assert "MTA-07" in range_a.assets
    assert range_a.is_asset_approved("MTA-07") is True

    # Test reservation and release
    reserved = mgr.reserve_range("RANGE-A", scenario_id="SCN-TEST")
    assert reserved.status == RangeStatus.ACTIVE
    assert reserved.active_scenario_id == "SCN-TEST"

    mgr.release_range("RANGE-A")
    assert range_a.status == RangeStatus.IDLE


def test_isolation_controller():
    mgr = RangeManager()
    range_a = mgr.get_range("RANGE-A")
    iso = mgr.isolation_controller

    # Approved target in Range-A
    assert iso.validate_target_in_range(range_a, "MTA-07") is True
    assert iso.validate_target_in_range(range_a, "10.200.1.7") is True

    # Unapproved or external target should raise RangeIsolationViolation
    with pytest.raises(RangeIsolationViolation):
        iso.validate_target_in_range(range_a, "192.168.1.100")

    # Production leakage prevention
    assert iso.verify_no_production_leakage(range_a, "10.200.1.50") is True
    assert iso.verify_no_production_leakage(range_a, "127.0.0.1") is True

    with pytest.raises(RangeIsolationViolation):
        iso.verify_no_production_leakage(range_a, "8.8.8.8")


def test_snapshot_and_rollback():
    mgr = RangeManager()
    range_a = mgr.get_range("RANGE-A")
    mta7 = range_a.get_asset("MTA-07")

    # Original state
    orig_cert = mta7.state_snapshot.get("cert_serial")

    # Capture snapshot
    snap_id = mgr.teardown_controller.take_snapshot(range_a)
    assert snap_id is not None

    # Mutate state during attack simulation
    mta7.state_snapshot["cert_serial"] = "ROGUE-ATTACKER-SERIAL-666"
    assert mta7.state_snapshot["cert_serial"] == "ROGUE-ATTACKER-SERIAL-666"

    # Restore snapshot
    success = mgr.teardown_controller.restore_snapshot(range_a, snap_id)
    assert success is True
    assert mta7.state_snapshot["cert_serial"] == orig_cert
