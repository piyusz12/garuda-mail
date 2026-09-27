"""
Tests for Phase 25 SOAR Playbooks Registry and Trigger Matching.
"""

import pytest
from security_operations.playbooks.models import PlaybookRegistry, SecurityPlaybook


def test_playbook_registry_defaults():
    registry = PlaybookRegistry()
    playbooks = registry.list_playbooks()
    assert len(playbooks) >= 4

    p1 = registry.get("PLAYBOOK-001")
    assert p1 is not None
    assert p1.trigger_event == "tls_downgrade"
    assert len(p1.steps) >= 3
    assert len(p1.rollback_steps) >= 1
    assert "ZERO_LEGACY_TLS_SESSIONS" in p1.verification_checks


def test_playbook_trigger_matching():
    registry = PlaybookRegistry()

    pb_cert = registry.find_by_trigger("certificate_change")
    assert pb_cert.playbook_id == "PLAYBOOK-002"

    pb_ja4 = registry.find_by_trigger("new_ja4")
    assert pb_ja4.playbook_id == "PLAYBOOK-003"

    pb_crypto = registry.find_by_trigger("crypto_regression")
    assert pb_crypto.playbook_id == "PLAYBOOK-006"
