"""
Effective Data Access Calculator.
Components 29.9 & 29.22: Resolves direct, group, workload-derived, and transitive access to sensitive data.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from data_security.access.graph import DataAccessGraph, DataAccessBinding
from data_graph.traversal import DataGraph


@dataclass
class EffectiveAccessReport:
    target_asset_id: str
    direct_identities: List[str]
    workload_derived_identities: List[str]
    transitive_access_paths: List[Dict[str, Any]]
    total_effective_identities_count: int
    is_access_excessive: bool
    risk_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_asset_id": self.target_asset_id,
            "direct_identities": self.direct_identities,
            "workload_derived_identities": self.workload_derived_identities,
            "transitive_access_paths": self.transitive_access_paths,
            "total_effective_identities_count": self.total_effective_identities_count,
            "is_access_excessive": self.is_access_excessive,
            "risk_summary": self.risk_summary,
        }


class EffectiveAccessCalculator:
    """Calculates comprehensive effective access across identity, cloud, and data planes."""

    def __init__(self, access_graph: Optional[DataAccessGraph] = None, data_graph: Optional[DataGraph] = None):
        self.access_graph = access_graph or DataAccessGraph()
        self.data_graph = data_graph or DataGraph()

    def calculate_effective_access(self, asset_id: str) -> EffectiveAccessReport:
        bindings = self.access_graph.get_bindings_for_asset(asset_id)
        direct_ids = [b.identity_id for b in bindings if not b.workload_id]
        workload_ids = [b.identity_id for b in bindings if b.workload_id]

        paths = self.data_graph.find_effective_access_to_data(asset_id)
        transitive_dicts = [p.to_dict() for p in paths]

        all_unique = set(direct_ids + workload_ids + [p.start_node for p in paths])
        is_excessive = len(all_unique) > 5

        risk_summary = (
            f"HIGH EXPOSURE: {len(all_unique)} distinct identities and workloads can reach sensitive dataset {asset_id}."
            if is_excessive
            else f"CONTROLLED ACCESS: {len(all_unique)} authorized entities hold effective access to {asset_id}."
        )

        return EffectiveAccessReport(
            target_asset_id=asset_id,
            direct_identities=sorted(list(set(direct_ids))),
            workload_derived_identities=sorted(list(set(workload_ids))),
            transitive_access_paths=transitive_dicts,
            total_effective_identities_count=len(all_unique),
            is_access_excessive=is_excessive,
            risk_summary=risk_summary,
        )
