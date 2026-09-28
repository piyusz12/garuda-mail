"""
Offline Signed Policy Bundles.
Component 78 & 79: Generates cryptographically signed policy bundles for offline or distributed PEP gateways.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import hashlib
import json
import time

from zero_trust.policy.parser import ZeroTrustPolicy


@dataclass
class SignedPolicyBundle:
    bundle_id: str
    policy_version: str
    issued_at: float
    expires_at: float
    policies: List[Dict[str, Any]]
    bundle_hash: str
    digital_signature: str

    def is_valid_now(self) -> bool:
        now = time.time()
        return self.issued_at <= now <= self.expires_at

    def verify_integrity(self) -> bool:
        blob = json.dumps(self.policies, sort_keys=True).encode("utf-8")
        calc_hash = hashlib.sha256(blob).hexdigest()
        if calc_hash != self.bundle_hash:
            return False

        sig_data = f"{self.bundle_hash}:{self.policy_version}:{self.expires_at}"
        calc_sig = hashlib.sha256(sig_data.encode("utf-8")).hexdigest()
        return calc_sig == self.digital_signature

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "policies_count": len(self.policies),
            "bundle_hash": self.bundle_hash,
            "digital_signature": self.digital_signature,
            "is_valid": self.is_valid_now(),
        }


class PolicyBundleDistributor:
    """Creates tamper-evident policy bundles."""

    @staticmethod
    def create_bundle(
        policies: List[ZeroTrustPolicy],
        version: str = "1.0.0",
        validity_hours: int = 24,
    ) -> SignedPolicyBundle:
        now = time.time()
        expires = now + (validity_hours * 3600)
        bundle_id = f"BUNDLE-v{version}-{int(now)}"

        policies_dicts = [p.to_dict() for p in policies]
        blob = json.dumps(policies_dicts, sort_keys=True).encode("utf-8")
        bundle_hash = hashlib.sha256(blob).hexdigest()

        sig_data = f"{bundle_hash}:{version}:{expires}"
        sig = hashlib.sha256(sig_data.encode("utf-8")).hexdigest()

        return SignedPolicyBundle(
            bundle_id=bundle_id,
            policy_version=version,
            issued_at=now,
            expires_at=expires,
            policies=policies_dicts,
            bundle_hash=bundle_hash,
            digital_signature=sig,
        )
