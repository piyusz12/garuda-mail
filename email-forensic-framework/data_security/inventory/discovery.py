"""
Data Discovery and Asset Discovery Lifecycle.
Components 29.2, 29.8: Discovers schemas, tables, columns, objects, and message streams across clouds.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from data_security.inventory.normalization import DataAsset, DataAssetType, ClassificationLevel
from data_security.inventory.connectors import DataSourceConnector, DataSourceType


class DiscoveryState(str, Enum):
    DISCOVERED = "DISCOVERED"
    CLASSIFIED = "CLASSIFIED"
    VERIFIED = "VERIFIED"
    STALE = "STALE"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class DiscoveredResourceRecord:
    discovery_id: str
    asset_id: str
    connector_id: str
    state: DiscoveryState = DiscoveryState.DISCOVERED
    discovered_at: float = field(default_factory=time.time)
    verified_at: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)


class DataDiscoveryEngine:
    """Continuously discovers enterprise data stores, schemas, and object buckets."""

    def __init__(self):
        self._assets: Dict[str, DataAsset] = {}
        self._discovery_records: Dict[str, DiscoveredResourceRecord] = {}
        self._seed_default_enterprise_assets()

    def _seed_default_enterprise_assets(self) -> None:
        # DATA-8821: Core Customer Records in Production Aurora
        customer_tbl = DataAsset(
            data_asset_id="DATA-8821",
            name="customer_vault.customers",
            asset_type=DataAssetType.TABLE,
            environment="production",
            location="us-east-1",
            storage_system="PostgreSQL-Aurora",
            classification=ClassificationLevel.RESTRICTED,
            sensitivity_score=95.0,
            business_owner="customer-platform",
            technical_owner="database-team",
            security_owner="security-team",
            data_steward="steward-compliance@garuda.enterprise",
            encryption_at_rest=True,
            encryption_in_transit=True,
            kms_key_id="KMS-KEY-PQC-01",
            tokenization_status="RAW",
            retention_days=730,
            record_count=1_250_000,
            size_bytes=450_000_000,
            tags={"DataDomain": "Customer", "PII": "true", "PCI": "true"},
            schema_metadata={
                "columns": [
                    {"name": "customer_id", "type": "UUID", "is_pii": False},
                    {"name": "full_name", "type": "VARCHAR(255)", "is_pii": True},
                    {"name": "email", "type": "VARCHAR(255)", "is_pii": True},
                    {"name": "phone", "type": "VARCHAR(32)", "is_pii": True},
                    {"name": "payment_token", "type": "VARCHAR(128)", "is_pii": True},
                    {"name": "billing_address", "type": "TEXT", "is_pii": True},
                ],
                "database": "DATABASE-21",
                "table": "CUSTOMERS",
            },
        )
        self.register_asset(customer_tbl)

        # DATA-FORENSIC-01: Forensic Lake Evidence Vault
        forensic_vault = DataAsset(
            data_asset_id="DATA-FORENSIC-01",
            name="garuda-forensic-evidence-lake/raw-pcaps",
            asset_type=DataAssetType.DATA_LAKE,
            environment="production",
            location="us-east-1",
            storage_system="S3-ObjectLock",
            classification=ClassificationLevel.CONFIDENTIAL,
            sensitivity_score=80.0,
            business_owner="security-operations",
            technical_owner="lake-engineering",
            security_owner="secops@garuda.enterprise",
            encryption_at_rest=True,
            kms_key_id="KMS-KEY-PQC-01",
            record_count=8_400_000,
            size_bytes=12_000_000_000,
            tags={"Domain": "Forensics", "LegalHold": "true"},
        )
        self.register_asset(forensic_vault)

        # DATA-EXPORT-STAGING: Unapproved S3 Export Bucket (Test Exposure)
        staging_export = DataAsset(
            data_asset_id="DATA-EXPORT-993",
            name="garuda-public-export-dump/temp_export.csv",
            asset_type=DataAssetType.OBJECT,
            environment="production",
            location="us-east-1",
            storage_system="S3",
            classification=ClassificationLevel.RESTRICTED,
            sensitivity_score=90.0,
            business_owner="analytics-staging",
            technical_owner="infra-team",
            is_publicly_exposed=True,  # Deliberate DSPM finding
            record_count=500_000,
            size_bytes=65_000_000,
            tags={"Exposure": "Public", "Status": "Leaked"},
        )
        self.register_asset(staging_export)

    def register_asset(self, asset: DataAsset) -> None:
        self._assets[asset.data_asset_id] = asset
        record = DiscoveredResourceRecord(
            discovery_id=f"DISC-{asset.data_asset_id}",
            asset_id=asset.data_asset_id,
            connector_id="CONN-DEFAULT",
            state=DiscoveryState.VERIFIED,
        )
        self._discovery_records[asset.data_asset_id] = record

    def get_asset(self, data_asset_id: str) -> Optional[DataAsset]:
        return self._assets.get(data_asset_id)

    def list_assets(self, classification: Optional[ClassificationLevel] = None) -> List[DataAsset]:
        res = list(self._assets.values())
        if classification:
            res = [a for a in res if a.classification == classification]
        return res

    def get_discovery_record(self, asset_id: str) -> Optional[DiscoveredResourceRecord]:
        return self._discovery_records.get(asset_id)
