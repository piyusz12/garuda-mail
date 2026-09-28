"""Tests for Data Inventory, Connectors, Discovery Engine, and Catalog."""

import pytest
from data_security.inventory import (
    DataSourceConnector,
    DataSourceType,
    ConnectionStatus,
    DataAsset,
    DataAssetType,
    ClassificationLevel,
    DataNormalizer,
    DataDiscoveryEngine,
    DiscoveryState,
)
from data_security.catalog import (
    DataCatalog,
    DataOwnershipRegistry,
)


def test_connector_lifecycle():
    """Verify connector status, attributes, and serialization."""
    conn = DataSourceConnector(
        connector_id="CONN-AURORA-01",
        name="Production Aurora Cluster",
        source_type=DataSourceType.RELATIONAL_DB,
        target_uri="aurora-cluster.prod.internal:5432/customer_vault",
        region="us-east-1",
        account_id="AWS-771829102",
        status=ConnectionStatus.CONNECTED,
    )
    assert conn.status == ConnectionStatus.CONNECTED
    assert conn.source_type == DataSourceType.RELATIONAL_DB
    assert conn.region == "us-east-1"

    data = conn.to_dict()
    assert data["connector_id"] == "CONN-AURORA-01"
    assert data["status"] == "CONNECTED"


def test_asset_normalization():
    """Verify raw schema metadata normalizes into standardized DataAsset instances."""
    table_asset = DataNormalizer.normalize_database_table(
        table_name="customers",
        database_name="customer_vault",
        columns=[
            {"name": "customer_id", "type": "UUID"},
            {"name": "email", "type": "VARCHAR(255)"},
            {"name": "payment_token", "type": "VARCHAR(128)"},
        ],
        record_count=1250000,
        owner="customer-platform",
    )

    assert table_asset.data_asset_id.startswith("DATA-TBL-")
    assert table_asset.name == "customer_vault.customers"
    assert table_asset.asset_type == DataAssetType.TABLE
    assert table_asset.business_owner == "customer-platform"
    assert table_asset.record_count == 1250000

    obj_asset = DataNormalizer.normalize_storage_object(
        bucket_name="secure-analytics-export",
        object_key="daily_dump.parquet",
        size_bytes=4500000,
        is_public=False,
    )
    assert obj_asset.data_asset_id.startswith("DATA-OBJ-")
    assert obj_asset.asset_type == DataAssetType.OBJECT
    assert obj_asset.is_publicly_exposed is False


def test_data_discovery_engine():
    """Verify discovery engine pipeline and pre-seeded enterprise assets."""
    engine = DataDiscoveryEngine()
    assets = engine.list_assets()
    assert len(assets) >= 3

    # Check seeded asset DATA-8821
    cust_asset = engine.get_asset("DATA-8821")
    assert cust_asset is not None
    assert cust_asset.name == "customer_vault.customers"
    assert cust_asset.classification == ClassificationLevel.RESTRICTED
    assert cust_asset.asset_type == DataAssetType.TABLE

    # Register custom asset
    custom_asset = DataAsset(
        data_asset_id="DATA-TEST-99",
        name="test_lake_raw",
        asset_type=DataAssetType.DATA_LAKE,
        classification=ClassificationLevel.CONFIDENTIAL,
    )
    engine.register_asset(custom_asset)
    retrieved = engine.get_asset("DATA-TEST-99")
    assert retrieved is not None
    assert retrieved.classification == ClassificationLevel.CONFIDENTIAL

    record = engine.get_discovery_record("DATA-TEST-99")
    assert record is not None
    assert record.state == DiscoveryState.VERIFIED


def test_data_catalog_and_ownership():
    """Verify data catalog search and multi-stakeholder ownership records."""
    catalog = DataCatalog()
    ownership_reg = DataOwnershipRegistry()

    # Query DATA-8821 in catalog
    entry = catalog.get_catalog_entry("DATA-8821")
    assert entry is not None
    assert entry["classification"] == "RESTRICTED"
    assert entry["ownership_assignment"] is not None

    ownership = ownership_reg.get_ownership("DATA-8821")
    assert ownership is not None
    assert ownership.business_owner == "customer-platform"
    assert ownership.technical_owner == "database-team"
    assert ownership.security_owner == "security-team"

    # Search catalog by classification
    sensitive_assets = catalog.search_assets(classification=ClassificationLevel.RESTRICTED)
    assert any(a.data_asset_id == "DATA-8821" for a in sensitive_assets)

    # Search catalog by keyword
    pcap_assets = catalog.search_assets(query="pcap")
    assert any(a.data_asset_id == "DATA-FORENSIC-01" for a in pcap_assets)
