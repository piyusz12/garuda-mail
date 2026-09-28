"""
Data Security Graph Traversal Engine.
Components 29.9, 29.10, 29.67: Traverses access chains, data flows, and encryption dependencies.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from data_graph.nodes import DataGraphNode, DataGraphNodeType
from data_graph.edges import DataGraphEdge, DataGraphEdgeType


@dataclass
class DataPathStep:
    from_node: str
    edge_type: str
    to_node: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataGraphPath:
    path_id: str
    start_node: str
    target_node: str
    steps: List[DataPathStep]
    length: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "start_node": self.start_node,
            "target_node": self.target_node,
            "length": self.length,
            "steps": [
                {
                    "from_node": s.from_node,
                    "edge_type": s.edge_type,
                    "to_node": s.to_node,
                    "properties": s.properties,
                }
                for s in self.steps
            ],
            "chain_description": " -> ".join([self.start_node] + [s.to_node for s in self.steps]),
        }


class DataGraph:
    """Enterprise Data Security Graph mapping data entities, identities, workloads, and flows."""

    def __init__(self):
        self.nodes: Dict[str, DataGraphNode] = {}
        self.edges: Dict[str, List[DataGraphEdge]] = {}
        self.reverse_edges: Dict[str, List[DataGraphEdge]] = {}
        self._seed_default_graph()

    def _seed_default_graph(self):
        nodes = [
            DataGraphNode("USER-1192", DataGraphNodeType.USER, "Analyst Developer Identity", sensitivity_score=20.0),
            DataGraphNode("SERVICE-91", DataGraphNodeType.USER, "MTA Workload Service Identity", sensitivity_score=50.0),
            DataGraphNode("WORKLOAD-991", DataGraphNodeType.WORKLOAD, "MTA Edge Daemon", sensitivity_score=85.0),
            DataGraphNode("API-CUSTOMER", DataGraphNodeType.API, "Customer Vault API Gateway", sensitivity_score=75.0),
            DataGraphNode("DATABASE-21", DataGraphNodeType.DATABASE, "Aurora Customer DB", sensitivity_score=90.0),
            DataGraphNode("DATA-8821", DataGraphNodeType.TABLE, "customer_vault.customers", sensitivity_score=95.0),
            DataGraphNode("COL-PAYMENT-TOKEN", DataGraphNodeType.COLUMN, "payment_token", sensitivity_score=98.0),
            DataGraphNode("KMS-KEY-PQC-01", DataGraphNodeType.KEY, "ML-KEM-768 Customer Encryption Key", sensitivity_score=10.0),
            DataGraphNode("DEST-EXTERNAL-C2", DataGraphNodeType.DESTINATION, "unapproved-external.example", sensitivity_score=100.0),
        ]
        for n in nodes:
            self.add_node(n)

        edges = [
            DataGraphEdge("DE1", "USER-1192", "SERVICE-91", DataGraphEdgeType.AUTHORIZED_BY),
            DataGraphEdge("DE2", "SERVICE-91", "WORKLOAD-991", DataGraphEdgeType.READS),
            DataGraphEdge("DE3", "WORKLOAD-991", "API-CUSTOMER", DataGraphEdgeType.READS),
            DataGraphEdge("DE4", "API-CUSTOMER", "DATABASE-21", DataGraphEdgeType.READS),
            DataGraphEdge("DE5", "DATABASE-21", "DATA-8821", DataGraphEdgeType.CONTAINS),
            DataGraphEdge("DE6", "DATA-8821", "COL-PAYMENT-TOKEN", DataGraphEdgeType.CONTAINS),
            DataGraphEdge("DE7", "DATA-8821", "KMS-KEY-PQC-01", DataGraphEdgeType.ENCRYPTED_BY),
        ]
        for e in edges:
            self.add_edge(e)

    def add_node(self, node: DataGraphNode) -> None:
        self.nodes[node.node_id] = node
        if node.node_id not in self.edges:
            self.edges[node.node_id] = []
        if node.node_id not in self.reverse_edges:
            self.reverse_edges[node.node_id] = []

    def add_edge(self, edge: DataGraphEdge) -> None:
        if edge.source_id not in self.edges:
            self.edges[edge.source_id] = []
        self.edges[edge.source_id].append(edge)

        if edge.target_id not in self.reverse_edges:
            self.reverse_edges[edge.target_id] = []
        self.reverse_edges[edge.target_id].append(edge)

    def find_paths(self, start_id: str, target_id: str, max_depth: int = 6) -> List[DataGraphPath]:
        results: List[DataGraphPath] = []

        def dfs(current_id: str, visited: Set[str], current_steps: List[DataPathStep]):
            if current_id == target_id and current_steps:
                results.append(
                    DataGraphPath(
                        path_id=f"DPATH-{len(results) + 1}",
                        start_node=start_id,
                        target_node=target_id,
                        steps=list(current_steps),
                        length=len(current_steps),
                    )
                )
                return

            if len(current_steps) >= max_depth:
                return

            for edge in self.edges.get(current_id, []):
                if edge.target_id not in visited and edge.allowed:
                    visited.add(edge.target_id)
                    step = DataPathStep(
                        from_node=edge.source_id,
                        edge_type=edge.edge_type.value if isinstance(edge.edge_type, DataGraphEdgeType) else edge.edge_type,
                        to_node=edge.target_id,
                        properties=edge.properties,
                    )
                    current_steps.append(step)
                    dfs(edge.target_id, visited, current_steps)
                    current_steps.pop()
                    visited.remove(edge.target_id)

        dfs(start_id, {start_id}, [])
        return results

    def find_effective_access_to_data(self, target_data_id: str) -> List[DataGraphPath]:
        all_paths: List[DataGraphPath] = []
        for nid, node in self.nodes.items():
            if node.node_type in [DataGraphNodeType.USER, DataGraphNodeType.WORKLOAD, DataGraphNodeType.API]:
                if nid != target_data_id:
                    paths = self.find_paths(nid, target_data_id)
                    all_paths.extend(paths)
        return all_paths
