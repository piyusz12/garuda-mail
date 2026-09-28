"""
Cryptographic Key Metadata and PQC Key Intelligence Integration.
Component 29.27 & 29.28: Integrates with Phase 21 Post-Quantum Cryptography & KMS key management.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class KeyAlgorithm(str, Enum):
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"
    AES_256_GCM = "AES-256-GCM"
    RSA_4096 = "RSA-4096"
    LEGACY_RSA_2048 = "RSA-2048"


@dataclass
class KMSKeyMetadata:
    key_id: str
    alias: str
    algorithm: KeyAlgorithm
    is_pqc_compliant: bool = True
    rotation_days: int = 90
    last_rotated_at: float = field(default_factory=time.time)
    key_owner: str = "crypto-eng@garuda.enterprise"
    cloud_provider: str = "AWS"

    def is_rotation_due(self) -> bool:
        return (time.time() - self.last_rotated_at) > (self.rotation_days * 86400)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "alias": self.alias,
            "algorithm": self.algorithm.value,
            "is_pqc_compliant": self.is_pqc_compliant,
            "rotation_days": self.rotation_days,
            "last_rotated_at": self.last_rotated_at,
            "key_owner": self.key_owner,
            "is_rotation_due": self.is_rotation_due(),
        }
