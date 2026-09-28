"""
Software Build Provenance and Supply-Chain Lineage.
Component 12: Tracks Source -> Commit -> CI Build -> Artifact -> Image -> Deployment.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class BuildProvenance:
    provenance_id: str
    image_id: str
    source_repository: str
    commit_sha: str
    branch: str = "main"
    build_id: str = "BUILD-992"
    builder_id: str = "github-actions/runner-v2"
    builder_identity: str = "github-actions[bot]@garuda.enterprise"
    ci_pipeline_url: str = "https://ci.garuda.enterprise/builds/992"
    slsa_level: int = 3
    built_at: float = field(default_factory=time.time)
    reproducible_build: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provenance_id": self.provenance_id,
            "image_id": self.image_id,
            "source_repository": self.source_repository,
            "commit_sha": self.commit_sha,
            "branch": self.branch,
            "build_id": self.build_id,
            "builder_id": self.builder_id,
            "builder_identity": self.builder_identity,
            "ci_pipeline_url": self.ci_pipeline_url,
            "slsa_level": self.slsa_level,
            "reproducible_build": self.reproducible_build,
            "built_at": self.built_at,
        }


class ProvenanceTracker:
    """Maintains verifiable provenance records linking container artifacts to source commits."""

    def __init__(self):
        self._provenance: Dict[str, BuildProvenance] = {}
        self._load_defaults()

    def _load_defaults(self):
        p1 = BuildProvenance(
            provenance_id="PROV-BUILD-992",
            image_id="IMG-MTA-241",
            source_repository="https://github.com/garuda-enterprise/mta-edge",
            commit_sha="c4b91f0a2e3d4c5b6a7b8c9d0e1f2a3b4c5d6e7f",
            branch="release-v2.4",
            build_id="BUILD-992",
            slsa_level=3,
        )
        self._provenance[p1.provenance_id] = p1

    def get(self, provenance_id: str) -> Optional[BuildProvenance]:
        return self._provenance.get(provenance_id)

    def get_provenance(self, provenance_id: str) -> Optional[BuildProvenance]:
        return self.get(provenance_id)

    def verify_provenance(self, provenance_id: str) -> bool:
        return self.get(provenance_id) is not None

    def get_by_image(self, image_id: str) -> Optional[BuildProvenance]:
        for p in self._provenance.values():
            if p.image_id == image_id:
                return p
        return None

    def register(self, prov: BuildProvenance) -> None:
        self._provenance[prov.provenance_id] = prov
