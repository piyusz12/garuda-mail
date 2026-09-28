"""
Key-to-Data Mapping Engine.
Component 29.28: Maps cryptographic KMS keys directly to databases, tables, and data assets.
"""
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any
from data_security.encryption.keys import KMSKeyMetadata, KeyAlgorithm


class KeyToDataMapper:
    """Maintains associations between KMS cryptographic keys and protected data assets."""

    def __init__(self):
        # key_id -> KMSKeyMetadata
        self._keys: Dict[str, KMSKeyMetadata] = {}
        # key_id -> list of asset_ids
        self._key_to_assets: Dict[str, List[str]] = {}
        self._seed_default_keys()

    def _seed_default_keys(self):
        k1 = KMSKeyMetadata(
            key_id="KMS-KEY-PQC-01",
            alias="garuda-customer-vault-pqc",
            algorithm=KeyAlgorithm.ML_KEM_768,
            is_pqc_compliant=True,
            rotation_days=90,
        )
        self.register_key(k1)
        self.bind_key_to_asset("KMS-KEY-PQC-01", "DATA-8821")
        self.bind_key_to_asset("KMS-KEY-PQC-01", "DATA-FORENSIC-01")

    def register_key(self, key_meta: KMSKeyMetadata) -> None:
        self._keys[key_meta.key_id] = key_meta

    def bind_key_to_asset(self, key_id: str, asset_id: str) -> None:
        if key_id not in self._key_to_assets:
            self._key_to_assets[key_id] = []
        if asset_id not in self._key_to_assets[key_id]:
            self._key_to_assets[key_id].append(asset_id)

    def get_assets_for_key(self, key_id: str) -> List[str]:
        return self._key_to_assets.get(key_id, [])

    def get_key_for_asset(self, asset_id: str) -> Optional[KMSKeyMetadata]:
        for kid, assets in self._key_to_assets.items():
            if asset_id in assets:
                return self._keys.get(kid)
        return None

    def trace_key_rotation_impact(self, key_id: str) -> Dict[str, Any]:
        """Identifies all datasets impacted by a key rotation or crypto migration."""
        key = self._keys.get(key_id)
        assets = self.get_assets_for_key(key_id)
        return {
            "key_id": key_id,
            "algorithm": key.algorithm.value if key else "UNKNOWN",
            "is_pqc_compliant": key.is_pqc_compliant if key else False,
            "total_protected_assets_count": len(assets),
            "protected_assets": assets,
            "rotation_safe": True,
        }
