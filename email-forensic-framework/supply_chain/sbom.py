"""
Software Bill of Materials (SBOM) Management.
Component 11: Tracks software dependencies, libraries, versions, and licenses linked to container images.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class SBOMPackage:
    name: str
    version: str
    purl: str  # Package URL (e.g., "pkg:pypi/cryptography@42.0.5")
    license: str = "Apache-2.0"
    is_direct_dependency: bool = True
    vulnerabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "license": self.license,
            "is_direct": self.is_direct_dependency,
            "vulnerabilities": self.vulnerabilities,
        }


@dataclass
class SoftwareBillOfMaterials:
    sbom_id: str
    image_id: str
    format: str = "CycloneDX-1.5"
    packages: List[SBOMPackage] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def total_packages(self) -> int:
        return len(self.packages)

    def find_package(self, package_name: str) -> Optional[SBOMPackage]:
        for p in self.packages:
            if p.name.lower() == package_name.lower():
                return p
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sbom_id": self.sbom_id,
            "image_id": self.image_id,
            "format": self.format,
            "packages_count": len(self.packages),
            "packages": [p.to_dict() for p in self.packages],
            "created_at": self.created_at,
        }


class SBOMManager:
    """Stores and analyzes SBOM documents for enterprise container images."""

    def __init__(self):
        self._sboms: Dict[str, SoftwareBillOfMaterials] = {}
        self._load_defaults()

    def _load_defaults(self):
        sbom_mta = SoftwareBillOfMaterials(
            sbom_id="SBOM-MTA-241",
            image_id="IMG-MTA-241",
            packages=[
                SBOMPackage(name="cryptography", version="42.0.5", purl="pkg:pypi/cryptography@42.0.5", license="Apache-2.0"),
                SBOMPackage(name="pydantic", version="2.7.1", purl="pkg:pypi/pydantic@2.7.1", license="MIT"),
                SBOMPackage(name="openssl", version="3.0.13", purl="pkg:deb/debian/openssl@3.0.13", license="Apache-2.0"),
                SBOMPackage(name="libssl3", version="3.0.13", purl="pkg:deb/debian/libssl3@3.0.13", license="OpenSSL"),
            ],
        )
        self._sboms[sbom_mta.sbom_id] = sbom_mta

    def get(self, sbom_id: str) -> Optional[SoftwareBillOfMaterials]:
        return self._sboms.get(sbom_id)

    def get_sbom(self, sbom_id: str) -> Optional[SoftwareBillOfMaterials]:
        return self.get(sbom_id)

    def get_by_image(self, image_id: str) -> Optional[SoftwareBillOfMaterials]:
        for s in self._sboms.values():
            if s.image_id == image_id:
                return s
        return None

    def register(self, sbom: SoftwareBillOfMaterials) -> None:
        self._sboms[sbom.sbom_id] = sbom

    def find_images_with_package(self, package_name: str) -> List[str]:
        matching = []
        for s in self._sboms.values():
            if s.find_package(package_name):
                matching.append(s.image_id)
        return matching
