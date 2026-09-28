"""
Tests for Phase 25 Autonomy Levels, Hard Guardrails, and Response Policy Rules.
"""

import pytest
from security_operations.automation.autonomy import AutonomyLevel
from security_operations.automation.guardrails import AutomationGuardrails, GuardrailEnforcer
from security_operations.automation.policies import ResponsePolicyEngine


def test_guardrails_protection_boundaries():
    enforcer = GuardrailEnforcer(AutomationGuardrails(max_affected_assets=3, max_actions_per_hour=5))

    # 1. Scope violation
    passed, msg = enforcer.check_guardrails("MTA-07", "GATEWAY", affected_count=10)
    assert not passed
    assert "Scope limit exceeded" in msg

    # 2. Protected asset class violation
    passed2, msg2 = enforcer.check_guardrails("ROOT-CA-01", "PRIMARY_ROOT_CA", affected_count=1)
    assert not passed2
    assert "protected by hard guardrails" in msg2

    # 3. Valid non-critical action
    passed3, msg3 = enforcer.check_guardrails("MTA-07", "RELAY", affected_count=1)
    assert passed3 is True


def test_response_policy_engine_lookup():
    pe = ResponsePolicyEngine()
    rule_tls = pe.get_rule("tls_downgrade")
    assert rule_tls is not None
    assert rule_tls.allowed_autonomy_level == AutonomyLevel.LEVEL_3_LOW_IMPACT
    assert rule_tls.require_canary is True
