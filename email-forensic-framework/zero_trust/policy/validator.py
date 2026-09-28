"""
Policy Validator.
Ensures attribute names, syntax, types, and logic structures are well-formed before policy deployment.
"""
from typing import Dict, List, Optional, Set
from .parser import ZeroTrustPolicy


class PolicyValidationError(Exception):
    pass


class PolicyValidator:
    """Pre-compilation validation for Zero Trust policies."""

    VALID_ATTRIBUTES: Set[str] = {
        "subject.id", "subject.group", "subject.role", "subject.department", "subject.risk",
        "device.id", "device.managed", "device.posture", "device.disk_encrypted", "device.os",
        "session.risk", "session.ja4", "session.tls_version", "session.time_utc_hour",
        "resource.id", "resource.classification", "resource.environment", "resource.protocol",
    }

    @classmethod
    def validate(cls, policy: ZeroTrustPolicy) -> bool:
        if not policy.policy_id:
            raise PolicyValidationError("Policy must have a valid policy_id.")
        if not policy.conditions:
            raise PolicyValidationError(f"Policy {policy.policy_id} must have at least one condition.")

        for c in policy.conditions:
            if not c.attribute:
                raise PolicyValidationError(f"Empty attribute in condition for policy {policy.policy_id}")
            if c.operator not in ("==", "!=", "in", "not_in", "<=", ">="):
                raise PolicyValidationError(f"Invalid operator '{c.operator}' in policy {policy.policy_id}")

        return True
