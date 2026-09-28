"""Tests for Encryption Intelligence, Key Mapping, Retention Expiry, and Verified Deletion."""

import pytest
import time
from data_security.inventory import DataAsset, DataAssetType, ClassificationLevel
from data_security.encryption import (
    KeyToDataMapper,
    EncryptionCoverageAuditor,
    KMSKeyMetadata,
    KeyAlgorithm,
)
from data_security.retention import (
    RetentionExpiryAuditor,
    DataDeletionVerificationEngine,
    DeletionLifecycleStage,
)


def test_encryption_key_mapping_and_coverage():
    """Verify Key-to-Data binding and crypto posture coverage audit."""
    mapper = KeyToDataMapper()

    # Verify registered PQC-resistant key for DATA-8821
    key_meta = mapper.get_key_for_asset("DATA-8821")
    assert key_meta is not None
    assert key_meta.key_id == "KMS-KEY-PQC-01"
    assert key_meta.is_pqc_compliant is True
    assert key_meta.algorithm == KeyAlgorithm.ML_KEM_768

    # Verify finding affected datasets when key changes
    affected_assets = mapper.get_assets_for_key("KMS-KEY-PQC-01")
    assert "DATA-8821" in affected_assets

    impact = mapper.trace_key_rotation_impact("KMS-KEY-PQC-01")
    assert impact["total_protected_assets_count"] >= 2

    # Encryption coverage audit
    auditor = EncryptionCoverageAuditor()
    sample_assets = [
        DataAsset(
            data_asset_id="DATA-8821",
            name="customers",
            asset_type=DataAssetType.TABLE,
            business_owner="customer-platform",
            classification=ClassificationLevel.RESTRICTED,
            encryption_at_rest=True,
            encryption_in_transit=True,
            kms_key_id="KMS-KEY-PQC-01",
        ),
        DataAsset(
            data_asset_id="DATA-LEGACY-02",
            name="legacy_backup",
            asset_type=DataAssetType.BACKUP,
            business_owner="infra",
            classification=ClassificationLevel.SENSITIVE,
            encryption_at_rest=False,  # Unencrypted sensitive data
            encryption_in_transit=True,
        ),
    ]

    report = auditor.audit_coverage(sample_assets)
    assert report.total_assets == 2
    assert report.encrypted_at_rest_pct == 50.0
    assert "DATA-LEGACY-02" in report.unencrypted_sensitive_assets


def test_retention_expiry_auditor():
    """Verify retention policy evaluation and detection of expired sensitive data."""
    auditor = RetentionExpiryAuditor()
    now = time.time()

    # 45-day old asset with 30-day retention limit
    old_log = DataAsset(
        data_asset_id="DATA-OLD-LOG-01",
        name="access_logs_august",
        asset_type=DataAssetType.LOG,
        business_owner="infra",
        classification=ClassificationLevel.INTERNAL,
        retention_days=30,
        created_at=now - (45 * 86400),
    )

    # Compliant 10-day old asset with 30-day retention
    fresh_log = DataAsset(
        data_asset_id="DATA-FRESH-LOG-02",
        name="access_logs_september",
        asset_type=DataAssetType.LOG,
        business_owner="infra",
        classification=ClassificationLevel.INTERNAL,
        retention_days=30,
        created_at=now - (10 * 86400),
    )

    findings = auditor.audit_assets([old_log, fresh_log])
    assert len(findings) == 1
    assert findings[0].asset_id == "DATA-OLD-LOG-01"
    assert findings[0].overdue_days >= 14


def test_data_deletion_verification_lifecycle():
    """Verify multi-step deletion attestation across metadata, access, replicas, and backup."""
    engine = DataDeletionVerificationEngine()

    attestation = engine.execute_verified_deletion(
        asset_id="DATA-DEPRECATED-LOGS",
        storage_system="S3-ObjectLock",
    )

    assert attestation.asset_id == "DATA-DEPRECATED-LOGS"
    assert attestation.stage == DeletionLifecycleStage.VERIFIED
    assert attestation.metadata_scrubbed is True
    assert attestation.replicas_purged is True
    assert attestation.backup_tombstoned is True
    assert len(attestation.verification_hash) == 64  # SHA-256
