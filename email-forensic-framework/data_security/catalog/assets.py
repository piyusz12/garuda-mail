"""
Enterprise Data Catalog.
Component 29.7: Central searchable registry of enterprise data assets, ownership, encryption, and sensitivity.
"""
from typing import Dict, List, Optional, Any
from data_security.inventory.normalization import DataAsset, ClassificationLevel, DataAssetType
from data_security.inventory.discovery import DataDiscoveryEngine
from data_security.catalog.owners import DataOwnershipRegistry


class DataCatalog:
    """Enterprise Data Catalog providing multi-dimensional search and querying."""

    def __init__(
        self,
        discovery_engine: Optional[DataDiscoveryEngine] = None,
        ownership_registry: Optional[DataOwnershipRegistry] = None,
    ):
        self.discovery = discovery_engine or DataDiscoveryEngine()
        self.ownership = ownership_registry or DataOwnershipRegistry()

    def search_assets(
        self,
        query: Optional[str] = None,
        classification: Optional[ClassificationLevel] = None,
        storage_system: Optional[str] = None,
        owner: Optional[str] = None,
        min_sensitivity: float = 0.0,
    ) -> List[DataAsset]:
        results = self.discovery.list_assets()

        if query:
            q = query.lower()
            results = [a for a in results if q in a.name.lower() or q in a.data_asset_id.lower()]

        if classification:
            results = [a for a in results if a.classification == classification]

        if storage_system:
            results = [a for a in results if storage_system.lower() in a.storage_system.lower()]

        if owner:
            results = [a for a in results if owner.lower() in a.business_owner.lower() or owner.lower() in a.technical_owner.lower()]

        if min_sensitivity > 0.0:
            results = [a for a in results if a.sensitivity_score >= min_sensitivity]

        return results

    def get_catalog_entry(self, data_asset_id: str) -> Optional[Dict[str, Any]]:
        asset = self.discovery.get_asset(data_asset_id)
        if not asset:
            return None
        owner_info = self.ownership.get_ownership(data_asset_id)
        data = asset.to_dict()
        data["ownership_assignment"] = owner_info.to_dict() if owner_info else None
        return data
