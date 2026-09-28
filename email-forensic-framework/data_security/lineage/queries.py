"""
Lineage Queries and Impact Analysis.
Component 29.8: Answers upstream provenance and downstream blast radius questions.
"""
from typing import Dict, List, Optional, Any
from data_security.lineage.graph import DataLineageGraph


class LineageQueryEngine:
    """Provides querying capabilities for data provenance and blast radius tracing."""

    def __init__(self, lineage_graph: Optional[DataLineageGraph] = None):
        self.graph = lineage_graph or DataLineageGraph()

    def trace_impact_of_breach(self, compromised_asset_id: str) -> Dict[str, Any]:
        """Identifies all downstream pipelines, warehouses, APIs, and dashboards affected by a data breach."""
        downstream = self.graph.get_downstream_dependents(compromised_asset_id)
        return {
            "compromised_asset": compromised_asset_id,
            "affected_downstream_count": len(downstream),
            "affected_downstream_entities": downstream,
            "blast_radius_rating": "CRITICAL" if len(downstream) > 3 else "MEDIUM",
        }

    def trace_origin_of_asset(self, target_asset_id: str) -> Dict[str, Any]:
        """Traces upstream primary data stores feeding into a given dataset or report."""
        upstream = self.graph.get_upstream_sources(target_asset_id)
        return {
            "target_asset": target_asset_id,
            "upstream_sources_count": len(upstream),
            "upstream_sources": upstream,
        }
