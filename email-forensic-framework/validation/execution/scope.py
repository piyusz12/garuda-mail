"""
Scope and Authorization Boundary Validator.
Guarantees that emulation targets are strictly within authorized defensive scope.
"""
from typing import Dict, List, Optional, Set
from validation.range.environments import RangeEnvironment


class ScopeViolationError(Exception):
    pass


class ScopeValidator:
    """Validates targets and techniques against white-listed operational boundaries."""

    def __init__(self, allowed_target_prefixes: Optional[List[str]] = None):
        self.allowed_prefixes = allowed_target_prefixes or ["MTA-", "RANGE-", "TEST-", "AUTH-", "STORAGE-"]
        self.blocked_targets: Set[str] = {"PROD-GATEWAY-01", "DC-PRIMARY", "CORP-CORE-SW01"}

    def validate_scope(self, target_assets: List[str], range_env: RangeEnvironment) -> bool:
        """Ensures every target asset is explicitly whitelisted in the active range."""
        for target in target_assets:
            if target in self.blocked_targets:
                raise ScopeViolationError(f"Target '{target}' is on the critical blocked assets list!")

            # Must exist in the designated range
            if target not in range_env.assets:
                raise ScopeViolationError(f"Target '{target}' is not allocated to range '{range_env.range_id}'.")

            asset = range_env.assets[target]
            if not asset.is_approved_target:
                raise ScopeViolationError(f"Asset '{target}' is present in range but NOT approved for emulation.")

        return True
