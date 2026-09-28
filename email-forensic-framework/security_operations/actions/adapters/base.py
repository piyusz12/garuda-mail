"""
Phase 25 — Response Adapter Base Interface
Standardizes execute, verify, validate, and rollback operations across all control domains.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from ..registry import ActionRecord


class BaseResponseAdapter(ABC):
    """Abstract interface for all control plane connectors and adapters."""

    @abstractmethod
    def validate(self, action: ActionRecord) -> bool:
        """Validates action schema, target reachability, and parameter bounds."""
        pass

    @abstractmethod
    def execute(self, action: ActionRecord) -> Dict[str, Any]:
        """Executes the action against the underlying infrastructure or service."""
        pass

    @abstractmethod
    def verify(self, action: ActionRecord) -> Dict[str, Any]:
        """Verifies whether the change took effect."""
        pass

    @abstractmethod
    def rollback(self, action: ActionRecord) -> Dict[str, Any]:
        """Reverts the change to the pre-execution snapshot state."""
        pass
