"""
Tests for Phase 27 — Policy Decision Point (PDP), Enforcement Point (PEP),
Service-to-Service Authorization, JIT/JEPA Privileges, Break-Glass & Governance.
"""

import time
import pytest

from zero_trust.policy.parser import (
    ZeroTrustPolicy,
    PolicyEffect,
    PolicyCondition,
)
from zero_trust.decision.context import AccessRequestContext, TrustContext
from zero_trust.decision.engine import PolicyDecisionPoint, AccessDecisionRecord
from zero_trust.decision.explain import PolicyDecisionExplainer
from zero_trust.enforcement.proxy import (
    PolicyEnforcementPoint,
    EnforcementAction,
    EnforcementResult,
)
from zero_trust.enforcement.gateway import ServiceToServiceGateway
from zero_trust.privilege.jit import (
    JITRequest,
    JITStatus,
    JITAccessManager,
)
from zero_trust.privilege.jepa import JEPAScoper
from zero_trust.privilege.emergency import (
    BreakGlassSession,
    BreakGlassStatus,
    EmergencyAccessController,
)
from zero_trust.governance.exceptions import PolicyExceptionManager
from zero_trust.governance.signed_bundle import PolicyBundleDistributor, SignedPolicyBundle
from zero_trust.governance.access_reviews import (
    AccessCertificationCampaign,
    ReviewDecision,
    AccessReviewItem,
)
from identity.lifecycle.access import AccessGrant


class TestPolicyDecisionPoint:
    def test_default_pdp_evaluation_allow(self):
        pdp = PolicyDecisionPoint()
        # Security ops on healthy managed device accessing FORENSIC-API -> ALLOW under POL-SOC-ADMIN
        ctx = AccessRequestContext(
            subject_id="ID-1192",
            subject_group="security-ops",
            subject_role="SOC_ADMIN",
            device_id="DEVICE-44",
            device_managed=True,
            device_posture="HEALTHY",
            resource_id="FORENSIC-API",
            resource_classification="CRITICAL",
            action="read",
            session_risk="LOW",
        )
        record = pdp.evaluate_access(ctx)
        assert record.decision == "ALLOW"
        assert record.matched_policy_id == "POL-SOC-ADMIN"

        # Explanation
        exp = PolicyDecisionExplainer.explain(record)
        assert "Access permitted" in exp["summary"]

    def test_default_pdp_evaluation_deny_unmanaged(self):
        pdp = PolicyDecisionPoint()
        # Unmanaged device accessing critical system -> DENY under POL-BLOCK-UNMANAGED-CRITICAL (priority=1)
        ctx = AccessRequestContext(
            subject_id="ID-1192",
            subject_group="security-ops",
            subject_role="SOC_ADMIN",
            device_id="DEVICE-UNMANAGED",
            device_managed=False,
            device_posture="NONCOMPLIANT",
            resource_id="FORENSIC-API",
            resource_classification="CRITICAL",
            action="read",
            session_risk="LOW",
        )
        record = pdp.evaluate_access(ctx)
        assert record.decision == "DENY"
        assert record.matched_policy_id == "POL-BLOCK-UNMANAGED-CRITICAL"
        assert "Device is unmanaged" in record.risk_factors

    def test_default_pdp_step_up_on_high_session_risk(self):
        pdp = PolicyDecisionPoint()
        # Managed device but HIGH session risk -> STEP_UP under POL-STEPUP-RISKY-SESSION (priority=5)
        ctx = AccessRequestContext(
            subject_id="ID-1192",
            subject_group="security-ops",
            subject_role="SOC_ADMIN",
            device_id="DEVICE-44",
            device_managed=True,
            device_posture="HEALTHY",
            resource_id="FORENSIC-API",
            resource_classification="CRITICAL",
            action="read",
            session_risk="HIGH",
        )
        record = pdp.evaluate_access(ctx)
        assert record.decision == "STEP_UP"
        assert record.matched_policy_id == "POL-STEPUP-RISKY-SESSION"

    def test_default_deny_when_no_policy_matches(self):
        pdp = PolicyDecisionPoint()
        # Guest user trying to access unmapped internal service
        ctx = AccessRequestContext(
            subject_id="ID-UNKNOWN",
            subject_group="external-guests",
            subject_role="GUEST",
            device_id="DEVICE-99",
            device_managed=True,
            device_posture="HEALTHY",
            resource_id="INTERNAL-SECRET-VAULT",
            resource_classification="INTERNAL",
            action="read",
            session_risk="LOW",
        )
        record = pdp.evaluate_access(ctx)
        assert record.decision == "DENY"
        assert record.matched_policy_id is None
        assert any("Default Deny" in r for r in record.reasons)

    def test_audit_log_recording_and_caching(self):
        pdp = PolicyDecisionPoint()
        ctx = AccessRequestContext(
            subject_id="ID-1192",
            subject_group="security-ops",
            subject_role="SOC_ADMIN",
            device_id="DEVICE-44",
            device_managed=True,
            device_posture="HEALTHY",
            resource_id="FORENSIC-API",
            resource_classification="CRITICAL",
            action="read",
        )
        rec1 = pdp.evaluate_access(ctx, use_cache=True)
        assert rec1.cached is False

        rec2 = pdp.evaluate_access(ctx, use_cache=True)
        assert rec2.cached is True
        assert rec2.decision == rec1.decision

        audit = pdp.get_audit_log(10)
        assert len(audit) >= 2


class TestPolicyEnforcementPoint:
    def test_pep_forward_and_header_injection(self):
        pdp = PolicyDecisionPoint()
        pep = PolicyEnforcementPoint(pdp=pdp)
        ctx = AccessRequestContext(
            subject_id="ID-1192",
            subject_group="security-ops",
            subject_role="SOC_ADMIN",
            device_id="DEVICE-44",
            device_managed=True,
            device_posture="HEALTHY",
            resource_id="FORENSIC-API",
            resource_classification="CRITICAL",
            action="read",
        )
        res = pep.enforce(ctx)
        assert res.action == EnforcementAction.FORWARD
        assert res.status_code == 200
        assert "X-ZeroTrust-Identity" in res.headers_injected
        assert res.headers_injected["X-ZeroTrust-Identity"] == "ID-1192"

    def test_pep_challenge_and_block(self):
        pdp = PolicyDecisionPoint()
        pep = PolicyEnforcementPoint(pdp=pdp)
        # Block unmanaged critical
        ctx_unmanaged = AccessRequestContext(
            subject_id="ID-1192",
            subject_group="security-ops",
            subject_role="SOC_ADMIN",
            device_id="DEVICE-ROGUE",
            device_managed=False,
            device_posture="NONCOMPLIANT",
            resource_id="FORENSIC-API",
            resource_classification="CRITICAL",
            action="read",
        )
        res_block = pep.enforce(ctx_unmanaged)
        assert res_block.action == EnforcementAction.BLOCK
        assert res_block.status_code == 403

        # Challenge step-up
        ctx_stepup = AccessRequestContext(
            subject_id="ID-1192",
            subject_group="security-ops",
            subject_role="SOC_ADMIN",
            device_id="DEVICE-44",
            device_managed=True,
            device_posture="HEALTHY",
            resource_id="FORENSIC-API",
            resource_classification="CRITICAL",
            action="read",
            session_risk="HIGH",
        )
        res_challenge = pep.enforce(ctx_stepup)
        assert res_challenge.action == EnforcementAction.CHALLENGE_STEPUP
        assert res_challenge.status_code == 401


class TestServiceToServiceGateway:
    def test_east_west_service_authorization(self):
        pdp = PolicyDecisionPoint()
        s2s = ServiceToServiceGateway(pdp=pdp)

        # Authorized call: FORENSIC-API -> MTA-07
        res_auth = s2s.authorize_call(
            source_service_id="FORENSIC-API",
            target_service_id="MTA-07",
            action="read",
            client_cert_valid=True,
        )
        assert res_auth.action == EnforcementAction.FORWARD
        assert res_auth.status_code == 200

        # Unauthorized / challenged call with invalid cert
        res_unauth = s2s.authorize_call(
            source_service_id="UNTRUSTED-APP",
            target_service_id="MTA-07",
            action="read",
            client_cert_valid=False,
        )
        assert res_unauth.action in (EnforcementAction.CHALLENGE_STEPUP, EnforcementAction.BLOCK)
        assert res_unauth.status_code in (401, 403)


class TestPrivilegeManagement:
    def test_jit_access_lifecycle(self):
        jit = JITAccessManager()
        req = jit.request_access(
            identity_id="ID-1192",
            role_requested="SOC_ADMIN",
            target_resource="MTA-07",
            justification="Investigating high priority incident",
            duration_minutes=30,
        )
        assert req.status == JITStatus.REQUESTED
        assert req.is_currently_valid() is False

        # Approve
        approved = jit.approve_and_activate(req.request_id, approver_id="ID-2044")
        assert approved.status == JITStatus.ACTIVE
        assert approved.is_currently_valid() is True
        assert approved.approver_id == "ID-2044"

        # Revoke
        revoked = jit.revoke_access(req.request_id)
        assert revoked.status == JITStatus.REVOKED
        assert revoked.is_currently_valid() is False

    def test_jepa_least_privilege_scoping(self):
        assert JEPAScoper.is_action_authorized("SOC_ANALYST", "investigate") is True
        assert JEPAScoper.is_action_authorized("SOC_ANALYST", "read") is True
        assert JEPAScoper.is_action_authorized("SOC_ANALYST", "approve_action") is False
        assert JEPAScoper.is_action_authorized("SOC_ADMIN", "approve_action") is True

        scoped = JEPAScoper.get_scoped_actions("SOC_ANALYST")
        assert "investigate" in scoped
        assert "read" in scoped

    def test_emergency_break_glass_four_eyes(self):
        controller = EmergencyAccessController()

        # Requester cannot approve own break glass (Separation of duties)
        with pytest.raises(PermissionError):
            controller.activate_break_glass(
                requester_id="ID-1192",
                approver_id="ID-1192",
                incident_ref="OUTAGE-001",
                target_service="MTA-07",
                justification="Emergency loop termination",
            )

        # Valid break glass with independent approver
        session = controller.activate_break_glass(
            requester_id="ID-1192",
            approver_id="ID-2044",
            incident_ref="OUTAGE-001",
            target_service="MTA-07",
            justification="Emergency loop termination",
            duration_minutes=15,
        )
        assert session.status == BreakGlassStatus.ACTIVE
        assert session.is_active() is True

        controller.record_action(session.session_id, "Flushed MTA outbound queue")
        assert len(session.actions_performed) == 1

        # Post-incident review
        controller.complete_post_incident_review(
            session_id=session.session_id,
            reviewer_id="ID-AUDITOR",
            notes="Valid break-glass usage confirmed.",
        )
        assert session.status == BreakGlassStatus.POST_INCIDENT_REVIEWED


class TestZeroTrustGovernance:
    def test_policy_exceptions_with_expiration(self):
        mgr = PolicyExceptionManager()
        exc = mgr.grant_exception(
            policy_id="POL-BLOCK-UNMANAGED-CRITICAL",
            subject_id="ID-3088",
            resource_id="MTA-07",
            reason="Contractor temporary access during migration",
            owner_id="ID-2044",
            approver_id="ID-1192",
            duration_days=1,
            compensating_controls=["mTLS client cert required", "Dedicated jump host"],
        )
        assert exc.is_currently_valid() is True
        assert len(exc.compensating_controls) == 2

        # Revocation
        mgr.revoke_exception(exc.exception_id)
        assert exc.is_currently_valid() is False

    def test_signed_policy_bundle_verification(self):
        policies = [
            ZeroTrustPolicy(
                policy_id="POL-P1",
                name="P1",
                effect=PolicyEffect.ALLOW,
                conditions=[PolicyCondition("device.managed", "==", True)],
            ),
        ]
        bundle = PolicyBundleDistributor.create_bundle(policies, version="2.0.0", validity_hours=12)
        assert isinstance(bundle, SignedPolicyBundle)
        assert bundle.policy_version == "2.0.0"
        assert bundle.is_valid_now() is True
        assert bundle.verify_integrity() is True

        # Tampering detection
        tampered_policies = list(bundle.policies)
        tampered_policies[0]["effect"] = "DENY"
        bundle.policies = tampered_policies
        assert bundle.verify_integrity() is False

    def test_access_certification_campaign(self):
        campaign = AccessCertificationCampaign(
            campaign_name="Q3 Review",
            reviewer_id="ID-2044",
        )
        grant = AccessGrant(
            grant_id="G-101",
            identity_id="ID-1192",
            resource_id="FORENSIC-API",
            action="read",
        )
        campaign.populate_from_grants([grant])
        assert len(campaign.items) == 1

        item_id = list(campaign.items.keys())[0]
        reviewed = campaign.submit_decision(
            item_id=item_id,
            decision=ReviewDecision.CERTIFIED_KEEP,
            notes="Active SOC analyst requiring console access",
        )
        assert reviewed.decision == ReviewDecision.CERTIFIED_KEEP
        assert campaign.to_dict()["completed_items"] == 1
