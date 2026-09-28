"""
Data Lineage Graph.
Components 29.8 & 29.20: End-to-end provenance mapping from initial ingestion through downstream consumption.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from data_security.lineage.transformations import DataTransformation, TransformationType


@dataclass
class LineageNode:
    node_id: str
    label: str
    node_type: str  # "DATA_ASSET", "PIPELINE", "API", "DASHBOARD"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LineageEdge:
    edge_id: str
    source_id: str
    target_id: str
    relationship: str  # "DERIVED_FROM", "FEEDS_INTO", "PRODUCED_BY"
    transformation_id: Optional[str] = None


class DataLineageGraph:
    """Directed acyclic graph tracking dataset origin, pipeline transformations, and downstream dependents."""

    def __init__(self):
        self.nodes: Dict[str, LineageNode] = {}
        self.edges: List[LineageEdge] = []
        self._seed_default_lineage()

    def _seed_default_lineage(self):
        nodes = [
            LineageNode("DATA-8821", "customer_vault.customers (PostgreSQL)", "DATA_ASSET"),
            LineageNode("PIPELINE-ETL-01", "Daily Customer Warehouse ETL", "PIPELINE"),
            LineageNode("DATA-WH-CUSTOMERS", "Snowflake Customer Analytics Table", "DATA_ASSET"),
            LineageNode("API-REPORTING", "Executive Metrics API", "API"),
            LineageNode("APP-DASHBOARD", "Customer Operations Dashboard", "DASHBOARD"),
        ]
        for n in nodes:
            self.nodes[n.node_id] = n

        edges = [
            LineageEdge("LE1", "DATA-8821", "PIPELINE-ETL-01", "FEEDS_INTO"),
            LineageEdge("LE2", "PIPELINE-ETL-01", "DATA-WH-CUSTOMERS", "PRODUCED_BY"),
            LineageEdge("LE3", "DATA-WH-CUSTOMERS", "API-REPORTING", "FEEDS_INTO"),
            LineageEdge("LE4", "API-REPORTING", "APP-DASHBOARD", "FEEDS_INTO"),
        ]
        self.edges = edges

    def add_node(self, node: LineageNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, edge: LineageEdge) -> None:
        self.edges.append(edge)

    def get_downstream_dependents(self, start_node_id: str) -> List[str]:
        visited: Set[str] = set()
        queue = [start_node_id]

        while queue:
            curr = queue.pop(0)
            for e in self.edges:
                if e.source_id == curr and e.target_id not in visited:
                    visited.add(e.target_id)
                    queue.append(e.target_id)

        return list(visited)

    def get_upstream_sources(self, target_node_id: str) -> List[str]:
        visited: Set[str] = set()
        queue = [target_node_id]

        while queue:
            curr = queue.pop(0)
            for e in self.edges:
                if e.target_id == curr and e.source_id not in visited:
                    visited.add(e.source_id)
                    queue.append(e.source_id)

        return list(visited)
