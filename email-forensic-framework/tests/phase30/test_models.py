"""Tests for AI Models, Provenance, Integrity, Supply Chain, and Deployment."""

import pytest
from ai_security.inventory import ModelLifecycleStatus, AIAsset, AIAssetType
from ai_security.models import (
    ModelFormat,
    ModelMetadata,
    AIModelRegistry,
    ModelProvenanceRecord,
    ModelProvenanceTracker,
    ModelIntegrityAuditor,
    AISupplyChainFindingType,
    ModelSupplyChainScanner,
    ModelServingConfig,
    ModelDeploymentManager,
)


def test_model_registry_and_deprecation_lifecycle():
    """Verify registration, query, and deprecation lifecycle for AI models."""
    registry = AIModelRegistry()

    # Pre-seeded model
    m781 = registry.get_model("MODEL-781")
    assert m781 is not None
    assert m781.name == "qwen2.5-8b-instruct"
    assert m781.format == ModelFormat.GGUF
    assert m781.approved_for_production is True
    assert m781.lifecycle_status == ModelLifecycleStatus.ACTIVE

    # Register custom model
    custom = ModelMetadata(
        model_id="MODEL-LLAMA-70B",
        name="llama-3-70b-instruct",
        version="3.0",
        format=ModelFormat.SAFETENSORS,
        parameter_count="70B",
        context_window=8192,
        license="Meta-Llama-3",
        approved_for_production=True,
    )
    registry.register_model(custom)
    assert registry.get_model("MODEL-LLAMA-70B") is not None

    # Deprecation lifecycle
    dep = registry.set_lifecycle_status("MODEL-LLAMA-70B", ModelLifecycleStatus.DEPRECATED)
    assert dep.lifecycle_status == ModelLifecycleStatus.DEPRECATED
    assert dep.approved_for_production is False


def test_model_provenance_tracking():
    """Verify tracking of model source repositories, introducing engineers, and approval tickets."""
    tracker = ModelProvenanceTracker()
    prov = tracker.get_provenance("MODEL-781")
    assert prov is not None
    assert "internal-artifactory" in prov.source_repository
    assert "mlops-engineer" in prov.introduced_by
    assert prov.approved_by is not None
    assert prov.approval_ticket == "SECOPS-AI-7712"


def test_model_artifact_integrity_verification():
    """Verify SHA-256 verification and detection of model weight tampering."""
    auditor = ModelIntegrityAuditor()

    # Valid verified hash
    valid_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res_valid = auditor.verify_runtime_artifact("MODEL-781", valid_hash)
    assert res_valid.is_valid is True
    assert res_valid.status == "VERIFIED"

    # Tampered / poisoned artifact
    tampered_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    res_tampered = auditor.verify_runtime_artifact("MODEL-781", tampered_hash)
    assert res_tampered.is_valid is False
    assert res_tampered.status == "INTEGRITY_VIOLATION"
    assert "CRITICAL" in res_tampered.details


def test_model_supply_chain_scanning():
    """Verify supply chain scanner identifies unapproved models, untrusted sources, and tampered artifacts."""
    scanner = ModelSupplyChainScanner(approved_registries=["internal-artifactory/models"])

    findings = scanner.audit_model_deployment(
        model_id="MODEL-UNTRUSTED-99",
        source_url="https://unverified-thirdparty-cdn.com/models/weights.bin",
        is_in_registry=False,
        is_integrity_valid=False,
    )
    assert len(findings) >= 3
    finding_types = [f.finding_type for f in findings]
    assert AISupplyChainFindingType.UNAPPROVED_MODEL in finding_types
    assert AISupplyChainFindingType.UNKNOWN_SOURCE in finding_types
    assert AISupplyChainFindingType.HASH_TAMPERED in finding_types


def test_model_deployment_security_and_auth():
    """Verify model serving configuration and caller authorization."""
    mgr = ModelDeploymentManager()
    dep = mgr.get_deployment("DEP-VLLM-NODE04")
    assert dep is not None
    assert dep.host_node == "AI-NODE-04"
    assert dep.port == 8000
    assert dep.egress_network_allowed is False

    # Authorized caller
    auth_ok = mgr.is_caller_authorized("DEP-VLLM-NODE04", "AGENT-41")
    assert auth_ok is True

    # Unauthorized caller
    auth_bad = mgr.is_caller_authorized("DEP-VLLM-NODE04", "ANONYMOUS-ATTACKER")
    assert auth_bad is False
