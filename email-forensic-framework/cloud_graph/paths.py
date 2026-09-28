"""
Cloud Attack Path Analyzer & Effective Reachability.
Components 41, 42, 75: Traverses identity-to-workload-to-database attack vectors and calculates path risk.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from cloud_graph.nodes import CloudNode, CloudNodeType
from cloud_graph.edges import CloudEdge, CloudEdgeType


@dataclass
class AttackPathStep:
    from_node: str
    edge_type: str
    to_node: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    path_id: str
    start_node_id: str
    target_node_id: str
    steps: List[AttackPathStep]
    length: int
    path_risk_score: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "start_node_id": self.start_node_id,
            "target_node_id": self.target_node_id,
            "length": self.length,
            "path_risk_score": self.path_risk_score,
            "description": self.description,
            "steps": [
                {
                    "from_node": s.from_node,
                    "edge_type": s.edge_type,
                    "to_node": s.to_node,
                    "properties": s.properties,
                }
                for s in self.steps
            ],
        }


class CloudAttackPathAnalyzer:
    """Traverses and models attack paths from identity to cloud resources."""

    def __init__(self):
        self.nodes: Dict[str, CloudNode] = {}
        self.edges: Dict[str, List[CloudEdge]] = {}  # source_id -> list of outgoing edges
        self.reverse_edges: Dict[str, List[CloudEdge]] = {}  # target_id -> list of incoming edges
        self._seed_default_enterprise_topology()

    def _seed_default_enterprise_topology(self) -> None:
        """Seed topology for USER-1192 -> CLOUD-ROLE-22 -> K8S-CLUSTER-01 -> NAMESPACE-A -> WORKLOAD-991 -> DATABASE-A."""
        nodes = [
            CloudNode("USER-1192", CloudNodeType.USER, "External Developer Identity", risk_score=15.0),
            CloudNode("CLOUD-ROLE-22", CloudNodeType.IAM_ROLE, "K8s-Admin-Assumable-Role", risk_score=45.0),
            CloudNode("K8S-CLUSTER-01", CloudNodeType.K8S_CLUSTER, "Garuda-Production-K8s", risk_score=30.0),
            CloudNode("NAMESPACE-A", CloudNodeType.NAMESPACE, "prod-mail-ns", risk_score=20.0),
            CloudNode("WORKLOAD-991", CloudNodeType.WORKLOAD, "MTA-07 Edge Workload", risk_score=75.0),
            CloudNode("DATABASE-A", CloudNodeType.DATABASE, "Customer Forensic Database (DB-01)", risk_score=90.0),
            CloudNode("BUCKET-01", CloudNodeType.STORAGE_BUCKET, "garuda-forensic-evidence", risk_score=85.0),
        ]
        for n in nodes:
            self.add_node(n)

        edges = [
            CloudEdge("E1", "USER-1192", "CLOUD-ROLE-22", CloudEdgeType.ASSUMES),
            CloudEdge("E2", "CLOUD-ROLE-22", "K8S-CLUSTER-01", CloudEdgeType.ACCESSES),
            CloudEdge("E3", "K8S-CLUSTER-01", "NAMESPACE-A", CloudEdgeType.CONTAINS),
            CloudEdge("E4", "NAMESPACE-A", "WORKLOAD-991", CloudEdgeType.CONTAINS),
            CloudEdge("E5", "WORKLOAD-991", "DATABASE-A", CloudEdgeType.ACCESSES),
            CloudEdge("E6", "WORKLOAD-991", "BUCKET-01", CloudEdgeType.ACCESSES),
        ]
        for e in edges:
            self.add_edge(e)

    def add_node(self, node: CloudNode) -> None:
        self.nodes[node.node_id] = node
        if node.node_id not in self.edges:
            self.edges[node.node_id] = []
        if node.node_id not in self.reverse_edges:
            self.reverse_edges[node.node_id] = []

    def add_edge(self, edge: CloudEdge) -> None:
        if edge.source_id not in self.edges:
            self.edges[edge.source_id] = []
        self.edges[edge.source_id].append(edge)

        if edge.target_id not in self.reverse_edges:
            self.reverse_edges[edge.target_id] = []
        self.reverse_edges[edge.target_id].append(edge)

    def find_attack_paths(
        self,
        start_node_id: str,
        target_node_id: str,
        max_depth: int = 6,
    ) -> List[AttackPath]:
        """Depth-first search for valid paths from start_node to target_node."""
        results: List[AttackPath] = []

        def dfs(current_id: str, visited: Set[str], current_steps: List[AttackPathStep]):
            if current_id == target_node_id and current_steps:
                # Compute cumulative path risk
                base_risk = sum(self.nodes[s.to_node].risk_score for s in current_steps if s.to_node in self.nodes)
                avg_risk = min(100.0, (base_risk / max(1, len(current_steps))) * (1.0 + 0.1 * len(current_steps)))
                results.append(
                    AttackPath(
                        path_id=f"APATH-{len(results) + 1}",
                        start_node_id=start_node_id,
                        target_node_id=target_node_id,
                        steps=list(current_steps),
                        length=len(current_steps),
                        path_risk_score=round(avg_risk, 1),
                        description=f"Attack path traversing {len(current_steps)} hops to sensitive target {target_node_id}",
                    )
                )
                return

            if len(current_steps) >= max_depth:
                return

            for edge in self.edges.get(current_id, []):
                if edge.target_id not in visited and edge.allowed:
                    visited.add(edge.target_id)
                    step = AttackPathStep(
                        from_node=edge.source_id,
                        edge_type=edge.edge_type.value if isinstance(edge.edge_type, CloudEdgeType) else edge.edge_type,
                        to_node=edge.target_id,
                        properties=edge.properties,
                    )
                    current_steps.append(step)
                    dfs(edge.target_id, visited, current_steps)
                    current_steps.pop()
                    visited.remove(edge.target_id)

        dfs(start_node_id, {start_node_id}, [])
        return results

    def find_effective_access_to_resource(self, target_resource_id: str) -> List[AttackPath]:
        """Identifies all identities and workloads with reachable paths to a sensitive resource."""
        all_paths: List[AttackPath] = []
        for node_id, node in self.nodes.items():
            if node.node_type in [CloudNodeType.USER, CloudNodeType.SERVICE_ACCOUNT, CloudNodeType.IAM_ROLE, CloudNodeType.WORKLOAD]:
                if node_id != target_resource_id:
                    paths = self.find_attack_paths(node_id, target_resource_id)
                    all_paths.extend(paths)
        return all_paths
