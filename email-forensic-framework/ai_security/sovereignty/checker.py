"""Garuda Enterprise AI Security - Sovereign AI & Air-Gap Compliance.
Phase 30 Sections 30.50, 30.71, 30.72: Evaluates data residency,
local model deployment boundaries, and air-gapped sovereignty graph compliance.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time


class HostingEnvironmentType(str, Enum):
    ON_PREM_AIR_GAPPED = "ON_PREM_AIR_GAPPED"
    PRIVATE_VPC = "PRIVATE_VPC"
    SOVEREIGN_CLOUD = "SOVEREIGN_CLOUD"
    PUBLIC_COMMERCIAL_CLOUD = "PUBLIC_COMMERCIAL_CLOUD"
    EXTERNAL_SAAS = "EXTERNAL_SAAS"


@dataclass
class SovereigntyComponentSpec:
    component_id: str
    component_type: str  # "MODEL", "EMBEDDING", "RAG", "VECTOR_DB", "AGENT", "TOOL"
    hosting_type: HostingEnvironmentType
    jurisdiction_country: str  # e.g., "US", "DE", "IN", "EU"
    has_internet_egress: bool = False
    is_air_gapped: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "component_type": self.component_type,
            "hosting_type": self.hosting_type.value,
            "jurisdiction_country": self.jurisdiction_country,
            "has_internet_egress": self.has_internet_egress,
            "is_air_gapped": self.is_air_gapped,
        }


@dataclass
class SovereigntyComplianceReport:
    system_id: str
    is_sovereign_compliant: bool
    is_fully_air_gapped: bool
    sovereignty_score_pct: float
    violations: List[str]
    components: List[SovereigntyComponentSpec]
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "is_sovereign_compliant": self.is_sovereign_compliant,
            "is_fully_air_gapped": self.is_fully_air_gapped,
            "sovereignty_score_pct": self.sovereignty_score_pct,
            "violations": self.violations,
            "components_count": len(self.components),
            "components": [c.to_dict() for c in self.components],
            "evaluated_at": self.evaluated_at,
        }


class SovereignAIChecker:
    """Evaluates whether an AI pipeline satisfies sovereign boundaries and air-gapped constraints."""

    def __init__(self, target_sovereignty_jurisdiction: str = "IN"):
        self.target_jurisdiction = target_sovereignty_jurisdiction

    def evaluate_pipeline(
        self,
        system_id: str,
        components: List[SovereigntyComponentSpec],
        require_air_gap: bool = False,
    ) -> SovereigntyComplianceReport:
        violations = []
        air_gap_intact = True
        penalty = 0.0

        for comp in components:
            # Check jurisdiction
            if comp.jurisdiction_country != self.target_jurisdiction:
                violations.append(
                    f"Component '{comp.component_id}' ({comp.component_type}) hosted in foreign jurisdiction '{comp.jurisdiction_country}' (expected {self.target_jurisdiction})"
                )
                penalty += 20.0

            # Check public SaaS / External Cloud usage
            if comp.hosting_type in (HostingEnvironmentType.EXTERNAL_SAAS, HostingEnvironmentType.PUBLIC_COMMERCIAL_CLOUD):
                violations.append(
                    f"Component '{comp.component_id}' utilizes external non-sovereign host ({comp.hosting_type.value})"
                )
                penalty += 15.0

            # Check air-gap internet egress
            if comp.has_internet_egress:
                air_gap_intact = False
                if require_air_gap or comp.is_air_gapped:
                    violations.append(f"Component '{comp.component_id}' has active internet egress, violating air-gap policy")
                    penalty += 25.0

        score = max(0.0, min(100.0, 100.0 - penalty))
        compliant = len(violations) == 0

        return SovereigntyComplianceReport(
            system_id=system_id,
            is_sovereign_compliant=compliant,
            is_fully_air_gapped=air_gap_intact and compliant,
            sovereignty_score_pct=round(score, 1),
            violations=violations,
            components=components,
        )
