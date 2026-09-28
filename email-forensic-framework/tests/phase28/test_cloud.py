"""
Unit & Integration Tests for Phase 28 Cloud Modules.
Tests Cloud Inventory, Normalization, Posture Evaluation, Drift Detection, and Networking.
"""
import pytest
from cloud.inventory.accounts import CloudAccount, CloudAccountRepository, CloudProvider, EnvironmentType
from cloud.inventory.resources import CloudResource, CloudResourceRepository, CloudResourceType
from cloud.inventory.normalization import MultiCloudNormalizer
from cloud.posture.rules import PostureRule, PostureSeverity
from cloud.posture.evaluation import CloudPostureEvaluator
from cloud.posture.drift import ConfigurationDrift, CloudDriftDetector
from cloud.storage.buckets import StorageBucket, StorageBucketRepository
from cloud.storage.databases import CloudDatabase, DatabaseRepository
from cloud.networking.policies import CloudNetworkPolicyEvaluator
from cloud.networking.networks import SecurityGroup, SecurityGroupRule, RuleDirection


def test_cloud_account_registration():
    repo = CloudAccountRepository()
    account = CloudAccount(
        account_id="ACC-TEST-99",
        provider=CloudProvider.AWS,
        account_name="test-production-account",
        environment=EnvironmentType.PRODUCTION,
        owner="SecOps",
    )
    repo.register(account)
    retrieved = repo.get("ACC-TEST-99")
    assert retrieved is not None
    assert retrieved.account_name == "test-production-account"
    assert retrieved.provider == CloudProvider.AWS


def test_multi_cloud_normalization():
    normalizer = MultiCloudNormalizer()

    # AWS S3 bucket raw
    aws_raw = {
        "Name": "company-customer-vault",
        "Region": "us-east-1",
        "Tags": [{"Key": "Environment", "Value": "production"}],
        "PublicAccessBlock": False,
        "Encrypted": True,
    }
    res_aws = normalizer.normalize_aws_resource("s3_bucket", aws_raw, "123456789012")
    assert res_aws.resource_type == CloudResourceType.STORAGE_BUCKET
    assert res_aws.provider == CloudProvider.AWS
    assert res_aws.is_publicly_accessible is True
    assert res_aws.is_encrypted is True

    # GCP Cloud SQL raw
    gcp_raw = {
        "name": "forensic-db-replica",
        "region": "us-central1",
        "environment": "production",
        "ipAddresses": [{"type": "PRIMARY", "ipAddress": "10.0.4.12"}],
        "settings": {"ipConfiguration": {"authorizedNetworks": []}},
    }
    res_gcp = normalizer.normalize_gcp_resource("cloud_sql", gcp_raw, "garuda-prod-proj")
    assert res_gcp.resource_type == CloudResourceType.DATABASE
    assert res_gcp.provider == CloudProvider.GCP
    assert res_gcp.is_publicly_accessible is False


def test_cloud_posture_evaluation():
    evaluator = CloudPostureEvaluator()
    unencrypted_public_bucket = CloudResource(
        resource_id="BUCKET-UNSAFE-01",
        resource_type=CloudResourceType.STORAGE_BUCKET,
        provider=CloudProvider.AWS,
        region="us-east-1",
        account_id="123456789012",
        name="public-unencrypted-leak",
        is_encrypted=False,
        is_publicly_accessible=True,
    )
    findings = evaluator.evaluate_resource(unencrypted_public_bucket)
    assert len(findings) >= 2
    rule_ids = [f.rule_id for f in findings]
    assert "STORAGE_NO_ENCRYPTION" in rule_ids
    assert "STORAGE_PUBLIC_EXPOSURE" in rule_ids


def test_cloud_drift_detection():
    detector = CloudDriftDetector()
    drift = ConfigurationDrift(
        drift_id="DRIFT-001",
        resource_id="SG-PROD-MTA",
        drift_type="UNAPPROVED_SECURITY_GROUP_RULE",
        expected_state={"ingress_ports": [25, 465, 587]},
        actual_state={"ingress_ports": [25, 465, 587, 22]},
        severity=PostureSeverity.CRITICAL,
        detected_by="CloudDriftEngine",
    )
    detector.record_drift(drift)
    assert len(detector.list_drifts()) == 1
    retrieved = detector.get_drift("DRIFT-001")
    assert retrieved is not None
    assert retrieved.severity == PostureSeverity.CRITICAL
    assert 22 in retrieved.actual_state["ingress_ports"]


def test_cloud_network_policy_evaluator():
    evaluator = CloudNetworkPolicyEvaluator()
    unsafe_sg = SecurityGroup(
        sg_id="SG-TEST-EXPOSED",
        name="unsafe-web-sg",
        vpc_id="VPC-01",
        rules=[
            SecurityGroupRule(
                rule_id="R1",
                direction=RuleDirection.INGRESS,
                protocol="TCP",
                from_port=22,
                to_port=22,
                cidr="0.0.0.0/0",  # Public SSH
            ),
            SecurityGroupRule(
                rule_id="R2",
                direction=RuleDirection.INGRESS,
                protocol="TCP",
                from_port=443,
                to_port=443,
                cidr="0.0.0.0/0",
            ),
        ],
    )
    violations = evaluator.evaluate_security_group(unsafe_sg)
    assert len(violations) >= 1
    assert any("22" in str(v.description) or "SSH" in str(v.description) for v in violations)
