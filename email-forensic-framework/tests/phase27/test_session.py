"""
Tests for Phase 27 — Active Session Monitoring, Continuous Re-Evaluation & Mid-Session Revocation.
"""

import time
import pytest

from zero_trust.policy.parser import (
    ZeroTrustPolicy,
    PolicyEffect,
    PolicyCondition,
)
from zero_trust.decision.engine import PolicyDecisionPoint
from zero_trust.sessions.monitor import (
    ActiveSession,
    SessionStatus,
    SessionMonitor,
)
from zero_trust.sessions.reevaluate import (
    ReevaluationEvent,
    ReevaluationResult,
    ContinuousAccessEvaluator,
)
from zero_trust.sessions.revoke import SessionRevocationManager


class TestSessionMonitor:
    def test_session_registration_and_lookup(self):
        monitor = SessionMonitor()
        sess = ActiveSession(
            session_id="SESS-001",
            identity_id="ID-1192",
            device_id="DEVICE-44",
            service_id="FORENSIC-API",
            status=SessionStatus.ACTIVE,
            tls_version="TLS 1.3",
            ja4="t13d1516h2_8daaf6152771_000000000000",
            client_ip="10.200.1.44",
            device_posture_score=1.0,
            session_risk_score=10.0,
        )
        monitor.register_session(sess)

        retrieved = monitor.get_session("SESS-001")
        assert retrieved is not None
        assert retrieved.identity_id == "ID-1192"
        assert retrieved.device_id == "DEVICE-44"
        assert len(monitor.list_active_sessions()) == 1


class TestContinuousAccessEvaluator:
    def test_reevaluation_on_posture_changed_to_unmanaged(self):
        monitor = SessionMonitor()
        pdp = PolicyDecisionPoint()
        evaluator = ContinuousAccessEvaluator(monitor=monitor, pdp=pdp)

        sess = ActiveSession(
            session_id="SESS-002",
            identity_id="ID-1192",
            device_id="DEVICE-44",
            service_id="FORENSIC-API",
            status=SessionStatus.ACTIVE,
            client_ip="10.200.1.44",
        )
        monitor.register_session(sess)

        # Trigger POSTURE_CHANGED: device becomes unmanaged on critical service
        res = evaluator.trigger_reevaluation(
            session_id="SESS-002",
            event=ReevaluationEvent.POSTURE_CHANGED,
            updated_signals={
                "device_managed": False,
                "device_posture": "NONCOMPLIANT",
                "resource_classification": "CRITICAL",
            },
        )
        assert isinstance(res, ReevaluationResult)
        assert res.event == ReevaluationEvent.POSTURE_CHANGED
        assert res.new_decision == "DENY"
        assert res.action_taken == "REVOKE"
        assert sess.status == SessionStatus.REVOKED

    def test_reevaluation_on_session_anomaly(self):
        monitor = SessionMonitor()
        pdp = PolicyDecisionPoint()
        evaluator = ContinuousAccessEvaluator(monitor=monitor, pdp=pdp)

        sess = ActiveSession(
            session_id="SESS-003",
            identity_id="ID-1192",
            device_id="DEVICE-44",
            service_id="FORENSIC-API",
            status=SessionStatus.ACTIVE,
            client_ip="10.200.1.44",
        )
        monitor.register_session(sess)

        # Trigger SESSION_ANOMALY: high session risk
        res = evaluator.trigger_reevaluation(
            session_id="SESS-003",
            event=ReevaluationEvent.SESSION_ANOMALY,
            updated_signals={
                "device_managed": True,
                "device_posture": "HEALTHY",
                "session_risk": "HIGH",
                "resource_classification": "CRITICAL",
            },
        )
        assert res.event == ReevaluationEvent.SESSION_ANOMALY
        assert res.new_decision == "STEP_UP"
        assert res.action_taken == "STEP_UP"
        assert sess.status == SessionStatus.STEP_UP_PENDING


class TestSessionRevocationManager:
    def test_immediate_session_revocation(self):
        monitor = SessionMonitor()
        rev_mgr = SessionRevocationManager(monitor=monitor)

        sess = ActiveSession(
            session_id="SESS-004",
            identity_id="ID-1192",
            device_id="DEVICE-44",
            service_id="FORENSIC-API",
            status=SessionStatus.ACTIVE,
        )
        monitor.register_session(sess)

        revoked = rev_mgr.revoke_session(
            session_id="SESS-004",
            actor="SOC-LEAD-01",
            reason="Confirmed device compromise detected by EDR",
        )
        assert revoked.status == SessionStatus.REVOKED
        assert len(rev_mgr.list_revocations()) == 1

        rev_record = rev_mgr.list_revocations()[0]
        assert rev_record["session_id"] == "SESS-004"
        assert rev_record["actor"] == "SOC-LEAD-01"
        assert "Confirmed device compromise" in rev_record["reason"]

    def test_revocation_unknown_session_raises(self):
        monitor = SessionMonitor()
        rev_mgr = SessionRevocationManager(monitor=monitor)

        with pytest.raises(KeyError):
            rev_mgr.revoke_session("SESS-NONEXISTENT", "admin", "test")
