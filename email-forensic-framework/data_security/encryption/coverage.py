"""
Data Encryption Coverage and Posture Auditor.
Components 29.27 & 29.29: Audits at-rest, in-transit, column-level encryption, and tokenization status.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from data_security.inventory.normalization import DataAsset, ClassificationLevel


@dataclass
class EncryptionCoverageReport:
    total_assets: int
    encrypted_at_rest_pct: float
    encrypted_in_transit_pct: float
    pqc_protected_pct: float
    tokenized_assets_count: int
    unencrypted_sensitive_assets: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_assets": self.total_assets,
            "encrypted_at_rest_pct": self.encrypted_at_rest_pct,
            "encrypted_in_transit_pct": self.encrypted_in_transit_pct,
            "pqc_protected_pct": self.pqc_protected_pct,
            "tokenized_assets_count": self.tokenized_assets_count,
            "unencrypted_sensitive_assets": self.unencrypted_sensitive_assets,
        }


class EncryptionCoverageAuditor:
    """Calculates fleet-wide cryptographic posture and identifies unprotected sensitive assets."""

    def audit_coverage(self, assets: List[DataAsset]) -> EncryptionCoverageReport:
        if not assets:
            return EncryptionCoverageReport(0, 100.0, 100.0, 100.0, 0, [])

        total = len(assets)
        at_rest = sum(1 for a in assets if a.encryption_at_rest)
        in_transit = sum(1 for a in assets if a.encryption_in_transit)
        pqc = sum(1 for a in assets if a.kms_key_id and "PQC" in a.kms_key_id)
        tokenized = sum(1 for a in assets if a.tokenization_status in ("TOKENIZED", "PSEUDONYMIZED", "HASHED"))

        unencrypted_sensitive = [
            a.data_asset_id
            for a in assets
            if a.classification in (ClassificationLevel.RESTRICTED, ClassificationLevel.SENSITIVE) and not a.encryption_at_rest
        ]

        return EncryptionCoverageReport(
            total_assets=total,
            encrypted_at_rest_pct=round((at_rest / total) * 100, 1),
            encrypted_in_transit_pct=round((in_transit / total) * 100, 1),
            pqc_protected_pct=round((pqc / total) * 100, 1),
            tokenized_assets_count=tokenized,
            unencrypted_sensitive_assets=unencrypted_sensitive,
        )
