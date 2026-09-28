"""AI Model Artifact Integrity and Digest Verification.
Component 30.6 & 30.13: Verifies cryptographic SHA-256 hashes against approved baseline to detect tampering.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import hashlib
import time


@dataclass
class ModelIntegrityCheckResult:
    model_id: str
    expected_hash: str
    observed_hash: str
    is_valid: bool
    status: str  # "VERIFIED", "INTEGRITY_VIOLATION", "UNVERIFIED"
    details: str
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "expected_hash": self.expected_hash,
            "observed_hash": self.observed_hash,
            "is_valid": self.is_valid,
            "status": self.status,
            "details": self.details,
            "checked_at": self.checked_at,
        }


class ModelIntegrityAuditor:
    """Computes and validates artifact hashes for model weights and configuration files."""

    def __init__(self):
        # model_id -> approved SHA-256 digest
        self._approved_digests: Dict[str, str] = {
            "MODEL-781": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "EMBED-01": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        }

    def register_approved_digest(self, model_id: str, sha256_hash: str) -> None:
        self._approved_digests[model_id] = sha256_hash

    def verify_runtime_artifact(self, model_id: str, runtime_artifact_hash: str) -> ModelIntegrityCheckResult:
        expected = self._approved_digests.get(model_id)
        if not expected:
            return ModelIntegrityCheckResult(
                model_id=model_id,
                expected_hash="NONE",
                observed_hash=runtime_artifact_hash,
                is_valid=False,
                status="UNVERIFIED",
                details=f"Model {model_id} has no registered baseline digest in security catalog.",
            )

        if expected.lower() == runtime_artifact_hash.lower():
            return ModelIntegrityCheckResult(
                model_id=model_id,
                expected_hash=expected,
                observed_hash=runtime_artifact_hash,
                is_valid=True,
                status="VERIFIED",
                details=f"Model {model_id} runtime artifact hash matches verified catalog signature.",
            )
        else:
            return ModelIntegrityCheckResult(
                model_id=model_id,
                expected_hash=expected,
                observed_hash=runtime_artifact_hash,
                is_valid=False,
                status="INTEGRITY_VIOLATION",
                details=f"CRITICAL: Model {model_id} runtime artifact hash {runtime_artifact_hash} does not match expected {expected}! Possible weight poisoning or backdoor.",
            )
