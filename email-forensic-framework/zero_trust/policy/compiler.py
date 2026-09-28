"""
Policy Compiler & Runtime Evaluator.
Compiles policy rules into fast, deterministic in-memory evaluation chains.
"""
from typing import Dict, List, Optional, Any, Callable
from .parser import ZeroTrustPolicy, PolicyEffect


class CompiledPolicy:
    """Compiled policy with cached predicate evaluators."""

    def __init__(self, policy: ZeroTrustPolicy):
        self.policy = policy
        self._predicates: List[Callable[[Dict[str, Any]], bool]] = [
            cond.evaluate for cond in policy.conditions
        ]

    def matches(self, context: Dict[str, Any], service_id: str, action: str) -> bool:
        if not self.policy.is_active:
            return False

        # Service filter
        if "*" not in self.policy.target_services and service_id not in self.policy.target_services:
            return False

        # Action filter
        if "*" not in self.policy.target_actions and action not in self.policy.target_actions:
            return False

        # All conditions must hold
        for pred in self._predicates:
            if not pred(context):
                return False

        return True


class PolicyCompiler:
    """Compiles ZeroTrustPolicy sets into high-performance evaluators."""

    @staticmethod
    def compile(policy: ZeroTrustPolicy) -> CompiledPolicy:
        return CompiledPolicy(policy)

    @staticmethod
    def compile_all(policies: List[ZeroTrustPolicy]) -> List[CompiledPolicy]:
        # Sort by priority ascending (1 is higher priority than 100)
        sorted_p = sorted(policies, key=lambda p: p.priority)
        return [CompiledPolicy(p) for p in sorted_p]
