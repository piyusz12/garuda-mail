"""
Container Image Registry and Metadata Modeling.
Component 10: Tracks images, digests, tags, versions, and build associations.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class ContainerImage:
    image_id: str
    repository: str  # e.g., "garuda/mta-edge"
    tag: str         # e.g., "v2.4.1"
    digest: str      # e.g., "sha256:7f91a24d08e1f0e4b83c51f3ef4e5d6c7b8a9101112131415161718192021222"
    registry: str = "registry.garuda.enterprise"
    size_bytes: int = 145_000_000
    is_signed: bool = True
    sbom_id: Optional[str] = "SBOM-MTA-241"
    provenance_id: Optional[str] = "PROV-BUILD-992"
    vulnerabilities_count: int = 2
    critical_vulnerabilities_count: int = 0
    pushed_at: float = field(default_factory=time.time)

    def full_reference(self) -> str:
        return f"{self.registry}/{self.repository}:{self.tag}@{self.digest[:19]}..."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "repository": self.repository,
            "tag": self.tag,
            "digest": self.digest,
            "registry": self.registry,
            "is_signed": self.is_signed,
            "sbom_id": self.sbom_id,
            "provenance_id": self.provenance_id,
            "vulnerabilities_count": self.vulnerabilities_count,
            "critical_vulnerabilities_count": self.critical_vulnerabilities_count,
            "pushed_at": self.pushed_at,
        }


class ContainerImageRepository:
    """Registry for enterprise container images."""

    def __init__(self):
        self._images: Dict[str, ContainerImage] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            ContainerImage(
                image_id="IMG-MTA-241",
                repository="garuda/mta-edge",
                tag="v2.4.1",
                digest="sha256:7f91a24d08e1f0e4b83c51f3ef4e5d6c7b8a9101112131415161718192021222",
                is_signed=True,
                sbom_id="SBOM-MTA-241",
                provenance_id="PROV-BUILD-992",
                vulnerabilities_count=1,
                critical_vulnerabilities_count=0,
            ),
            ContainerImage(
                image_id="IMG-FORENSIC-310",
                repository="garuda/forensic-api",
                tag="v3.1.0",
                digest="sha256:5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b",
                is_signed=True,
                sbom_id="SBOM-FORENSIC-310",
                provenance_id="PROV-BUILD-993",
                vulnerabilities_count=0,
                critical_vulnerabilities_count=0,
            ),
            ContainerImage(
                image_id="IMG-SUSPICIOUS-LATEST",
                repository="unknown-registry/debug-tool",
                tag="latest",
                digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
                registry="docker.io",
                is_signed=False,  # Unsigned image
                sbom_id=None,     # No SBOM
                provenance_id=None,
                vulnerabilities_count=14,
                critical_vulnerabilities_count=3,
            ),
        ]
        for img in defaults:
            self._images[img.image_id] = img

    def get(self, image_id: str) -> Optional[ContainerImage]:
        if image_id in self._images:
            return self._images[image_id]
        for img in self._images.values():
            if img.repository == image_id or img.repository.endswith(f"/{image_id}") or img.image_id == image_id:
                return img
        return None

    def get_by_digest(self, digest: str) -> Optional[ContainerImage]:
        for img in self._images.values():
            if img.digest == digest:
                return img
        return None

    def list_all(self) -> List[ContainerImage]:
        return list(self._images.values())

    def register(self, image: ContainerImage) -> None:
        self._images[image.image_id] = image
