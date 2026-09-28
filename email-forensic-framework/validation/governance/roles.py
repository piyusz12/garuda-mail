"""
Governance Roles & Separation of Duties.
Enforces that no single identity can author, approve, and execute high-risk validation scenarios.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum


class GovernanceRole(str, Enum):
    SCENARIO_AUTHOR = "Scenario Author"
    SCENARIO_APPROVER = "Scenario Approver"
    SCENARIO_OPERATOR = "Scenario Operator"
    SECURITY_REVIEWER = "Security Reviewer"


class SeparationOfDutiesViolation(Exception):
    pass


class SeparationOfDutiesController:
    """Enforces multi-party governance for defensive adversary emulation."""

    @staticmethod
    def validate_execution_allowed(
        author_id: str,
        approver_id: Optional[str],
        operator_id: str,
        blast_radius: str,
    ) -> bool:
        # For LOW blast radius, self-execution in sandbox is permitted for dev/test
        if blast_radius == "LOW":
            return True

        # For MEDIUM and HIGH blast radius, strictly require approval and separate operator
        if not approver_id:
            raise SeparationOfDutiesViolation(
                f"Scenarios with {blast_radius} blast radius require an explicit Scenario Approver before execution."
            )

        if author_id == approver_id:
            raise SeparationOfDutiesViolation(
                f"Separation of Duties Violation: Author '{author_id}' cannot approve their own {blast_radius} scenario."
            )

        if operator_id == approver_id:
            raise SeparationOfDutiesViolation(
                f"Separation of Duties Violation: Approver '{approver_id}' cannot also operate/execute the {blast_radius} scenario."
            )

        return True
