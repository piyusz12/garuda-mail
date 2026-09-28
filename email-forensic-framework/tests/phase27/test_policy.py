"""
Tests for Phase 27 — Zero Trust Policy Engine, DSL Parser, Compiler, Validator & Conflict Detector.
"""

import pytest
from zero_trust.policy.parser import (
    ZeroTrustPolicy,
    PolicyEffect,
    PolicyCondition,
    PolicyDSLParser,
)
from zero_trust.policy.compiler import (
    PolicyCompiler,
    CompiledPolicy,
)
from zero_trust.policy.validator import (
    PolicyValidator,
    PolicyValidationError,
)
from zero_trust.policy.conflict import (
    PolicyConflictDetector,
    PolicyConflict,
)


class TestPolicyModelAndConditions:
    def test_condition_evaluation_operators(self):
        # Equality
        c_eq = PolicyCondition("device.managed", "==", True)
        assert c_eq.evaluate({"device.managed": True}) is True
        assert c_eq.evaluate({"device.managed": False}) is False

        # In and Not In
        c_in = PolicyCondition("session.risk", "in", ["LOW", "MEDIUM"])
        assert c_in.evaluate({"session.risk": "LOW"}) is True
        assert c_in.evaluate({"session.risk": "HIGH"}) is False

        c_nin = PolicyCondition("session.risk", "not_in", ["HIGH", "CRITICAL"])
        assert c_nin.evaluate({"session.risk": "LOW"}) is True
        assert c_nin.evaluate({"session.risk": "CRITICAL"}) is False

        # Nested dict resolution
        c_nested = PolicyCondition("subject.department", "==", "Security Operations")
        assert c_nested.evaluate({"subject": {"department": "Security Operations"}}) is True
        assert c_nested.evaluate({"subject": {"department": "Marketing"}}) is False

    def test_classification_hierarchy_comparison(self):
        # PUBLIC: 1, INTERNAL: 2, SENSITIVE: 3, CRITICAL: 4
        c_lte = PolicyCondition("resource.classification", "<=", "SENSITIVE")
        assert c_lte.evaluate({"resource.classification": "PUBLIC"}) is True
        assert c_lte.evaluate({"resource.classification": "INTERNAL"}) is True
        assert c_lte.evaluate({"resource.classification": "SENSITIVE"}) is True
        assert c_lte.evaluate({"resource.classification": "CRITICAL"}) is False

        c_gte = PolicyCondition("resource.classification", ">=", "SENSITIVE")
        assert c_gte.evaluate({"resource.classification": "SENSITIVE"}) is True
        assert c_gte.evaluate({"resource.classification": "CRITICAL"}) is True
        assert c_gte.evaluate({"resource.classification": "INTERNAL"}) is False


class TestPolicyDSLParser:
    def test_parse_text_dsl_allow(self):
        dsl_text = """
        ALLOW
        WHEN
          subject.group == "security-ops"
          AND device.managed == true
          AND device.posture == "HEALTHY"
        """
        policy = PolicyDSLParser.parse_dsl(dsl_text, "POL-TEST-01", "SecOps Allow Test")
        assert policy.policy_id == "POL-TEST-01"
        assert policy.effect == PolicyEffect.ALLOW
        assert len(policy.conditions) == 3
        assert policy.conditions[0].attribute == "subject.group"
        assert policy.conditions[0].value == "security-ops"
        assert policy.conditions[1].attribute == "device.managed"
        assert policy.conditions[1].value is True

    def test_parse_text_dsl_deny_and_stepup(self):
        deny_text = """
        DENY
        WHEN
          session.risk in ["HIGH", "CRITICAL"]
        """
        p_deny = PolicyDSLParser.parse_dsl(deny_text, "POL-TEST-DENY", "High Risk Deny")
        assert p_deny.effect == PolicyEffect.DENY
        assert len(p_deny.conditions) == 1

        stepup_text = """
        STEP_UP
        WHEN
          resource.classification == "CRITICAL"
          AND device.posture != "HEALTHY"
        """
        p_stepup = PolicyDSLParser.parse_dsl(stepup_text, "POL-TEST-STEPUP", "Critical StepUp")
        assert p_stepup.effect == PolicyEffect.STEP_UP
        assert len(p_stepup.conditions) == 2

    def test_parse_dict_and_to_dict(self):
        data = {
            "policy_id": "POL-DICT-01",
            "name": "Dict Policy",
            "effect": "ALLOW",
            "priority": 15,
            "target_services": ["MTA-07"],
            "target_actions": ["read", "connect"],
            "conditions": [
                {"attribute": "device.managed", "operator": "==", "value": True}
            ],
            "description": "Parsed from dict",
        }
        policy = PolicyDSLParser.parse_dict(data)
        assert policy.policy_id == "POL-DICT-01"
        assert policy.priority == 15
        assert policy.target_services == ["MTA-07"]

        d_out = policy.to_dict()
        assert d_out["policy_id"] == "POL-DICT-01"
        assert d_out["effect"] == "ALLOW"


class TestPolicyCompiler:
    def test_compilation_and_matching(self):
        policy = ZeroTrustPolicy(
            policy_id="POL-COMP-01",
            name="Compiler Test",
            effect=PolicyEffect.ALLOW,
            target_services=["MTA-07"],
            target_actions=["send", "relay"],
            conditions=[
                PolicyCondition("device.managed", "==", True),
                PolicyCondition("session.risk", "not_in", ["HIGH", "CRITICAL"]),
            ],
            priority=10,
        )
        cp = PolicyCompiler.compile(policy)
        assert isinstance(cp, CompiledPolicy)

        # Matching context
        matching_ctx = {
            "device.managed": True,
            "session.risk": "LOW",
        }
        assert cp.matches(matching_ctx, "MTA-07", "send") is True

        # Non-matching service
        assert cp.matches(matching_ctx, "OTHER-SVC", "send") is False

        # Non-matching action
        assert cp.matches(matching_ctx, "MTA-07", "delete") is False

        # Failing condition
        failing_ctx = {
            "device.managed": False,
            "session.risk": "LOW",
        }
        assert cp.matches(failing_ctx, "MTA-07", "send") is False


class TestPolicyValidator:
    def test_valid_policy(self):
        pol = ZeroTrustPolicy(
            policy_id="POL-VALID",
            name="Valid Policy",
            effect=PolicyEffect.ALLOW,
            conditions=[PolicyCondition("device.managed", "==", True)],
        )
        assert PolicyValidator.validate(pol) is True

    def test_missing_policy_id_or_empty_conditions(self):
        pol_no_id = ZeroTrustPolicy(
            policy_id="",
            name="No ID",
            effect=PolicyEffect.ALLOW,
            conditions=[PolicyCondition("device.managed", "==", True)],
        )
        with pytest.raises(PolicyValidationError):
            PolicyValidator.validate(pol_no_id)

        pol_no_cond = ZeroTrustPolicy(
            policy_id="POL-EMPTY",
            name="No Conditions",
            effect=PolicyEffect.ALLOW,
            conditions=[],
        )
        with pytest.raises(PolicyValidationError):
            PolicyValidator.validate(pol_no_cond)

    def test_invalid_operator(self):
        pol_bad_op = ZeroTrustPolicy(
            policy_id="POL-BAD-OP",
            name="Bad Operator",
            effect=PolicyEffect.ALLOW,
            conditions=[PolicyCondition("device.managed", "===INVALID===", True)],
        )
        with pytest.raises(PolicyValidationError):
            PolicyValidator.validate(pol_bad_op)


class TestPolicyConflictDetector:
    def test_detect_allow_vs_deny_conflict(self):
        p_allow = ZeroTrustPolicy(
            policy_id="POL-ALLOW-MTA",
            name="Allow MTA",
            effect=PolicyEffect.ALLOW,
            target_services=["MTA-07"],
            target_actions=["*"],
            conditions=[PolicyCondition("device.managed", "==", True)],
            priority=20,
        )
        p_deny = ZeroTrustPolicy(
            policy_id="POL-DENY-MTA",
            name="Deny MTA",
            effect=PolicyEffect.DENY,
            target_services=["MTA-07"],
            target_actions=["*"],
            conditions=[PolicyCondition("device.managed", "==", False)],
            priority=10,
        )
        conflicts = PolicyConflictDetector.detect_conflicts([p_allow, p_deny])
        assert len(conflicts) >= 1
        c = conflicts[0]
        assert "MTA-07" in c.overlapping_services
        assert (c.effect_a == "ALLOW" and c.effect_b == "DENY") or (c.effect_a == "DENY" and c.effect_b == "ALLOW")

    def test_no_conflict_when_effects_agree_or_services_disjoint(self):
        p1 = ZeroTrustPolicy(
            policy_id="POL-1",
            name="P1",
            effect=PolicyEffect.ALLOW,
            target_services=["SERVICE-A"],
            target_actions=["read"],
            conditions=[PolicyCondition("device.managed", "==", True)],
        )
        p2 = ZeroTrustPolicy(
            policy_id="POL-2",
            name="P2",
            effect=PolicyEffect.DENY,
            target_services=["SERVICE-B"],
            target_actions=["read"],
            conditions=[PolicyCondition("device.managed", "==", False)],
        )
        conflicts = PolicyConflictDetector.detect_conflicts([p1, p2])
        assert len(conflicts) == 0
