"""
Unit & Integration Tests for Phase 28 Supply Chain Modules.
Tests Container Images, SBOM parsing, Build Provenance, Cryptographic Signatures, and Vulnerability Prioritization.
"""
import pytest
from supply_chain.images import ContainerImage, ContainerImageRepository
from supply_chain.sbom import SBOMPackage, SoftwareBillOfMaterials, SBOMManager
from supply_chain.provenance import BuildProvenance, ProvenanceTracker
from supply_chain.signing import ImageSignature, ImageSignerVerifier
from supply_chain.vulnerabilities import VulnerabilityFinding, VulnerabilityPrioritizer


def test_sbom_manager_lookup():
    manager = SBOMManager()
    sbom = manager.get_sbom("SBOM-MTA-241")
    assert sbom is not None
    assert sbom.total_packages >= 3
    package_names = [p.name for p in sbom.packages]
    assert "golang.org/x/crypto" in package_names or "openssl" in package_names


def test_provenance_tracker_verification():
    tracker = ProvenanceTracker()
    prov = tracker.get_provenance("PROV-BUILD-992")
    assert prov is not None
    assert prov.commit_sha == "c4b91f0a2e3d4c5b6a7b8c9d0e1f2a3b4c5d6e7f"
    assert prov.builder_id == "github-actions/runner-v2"
    assert prov.slsa_level >= 3
    assert tracker.verify_provenance("PROV-BUILD-992") is True


def test_cryptographic_image_signing_and_verification():
    verifier = ImageSignerVerifier(signing_secret="unit-test-secret-salt-1234")
    digest = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

    # Before signing
    assert verifier.verify_signature(digest) is False

    # Sign digest
    sig = verifier.sign_digest(digest, signer="security-lead@garuda.enterprise")
    assert sig.signer_identity == "security-lead@garuda.enterprise"
    assert len(sig.signature_b64) > 10

    # Verify signature
    assert verifier.verify_signature(digest) is True


def test_contextual_vulnerability_prioritization():
    prioritizer = VulnerabilityPrioritizer()

    # Vulnerability A: High CVSS (8.0), but in dormant container, not exposed, not critical service
    vuln_dormant = VulnerabilityFinding(
        cve_id="CVE-2023-1111",
        package_name="libpng",
        installed_version="1.6.37",
        base_cvss=8.0,
        is_runtime_loaded=False,
        is_internet_exposed=False,
        service_criticality="LOW",
        has_public_exploit=False,
    )
    score_dormant = prioritizer.calculate_priority_score(vuln_dormant)

    # Vulnerability B: Moderate CVSS (7.5), but running in active workload, internet-facing, critical service, public exploit
    vuln_active = VulnerabilityFinding(
        cve_id="CVE-2024-45338",
        package_name="golang.org/x/crypto",
        installed_version="v0.21.0",
        base_cvss=7.5,
        is_runtime_loaded=True,
        is_internet_exposed=True,
        service_criticality="CRITICAL",
        has_public_exploit=True,
    )
    score_active = prioritizer.calculate_priority_score(vuln_active)

    # Contextual score should elevate active exposed vulnerability significantly higher
    assert score_active > score_dormant
    assert score_active >= 25.0
