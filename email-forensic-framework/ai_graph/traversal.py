"""AI Security Graph Traversal, Attack-Path Discovery, and Digital Twin Simulation.
Components 30.65, 30.66, 30.78 & 30.79: Traverses AI system relationships and detects AI data egress attack paths.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any

from ai_graph.nodes import AIGraphNode, AIGraphNodeType
from ai_graph.edges import AIGraphEdge, AIGraphEdgeType


@dataclass
class AIGraphPathStep:
    from_node: str
    edge_type: str
    to_node: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIGraphPath:
    path_id: str
    start_node: str
    target_node: str
    steps: List[AIGraphPathStep]
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


class AIGraph:
    """Enterprise AI Security Graph mapping users, agents, models, vector DBs, and tools."""

    def __init__(self):
        self.nodes: Dict[str, AIGraphNode] = {}
        self.edges: Dict[str, List[AIGraphEdge]] = {}
        self.reverse_edges: Dict[str, List[AIGraphEdge]] = {}
        self._seed_default_ai_graph()

    def _seed_default_ai_graph(self):
        nodes = [
            AIGraphNode("USER-1192", AIGraphNodeType.USER, "Analyst User Identity", sensitivity_score=20.0),
            AIGraphNode("SERVICE-IDENTITY-77", AIGraphNodeType.IDENTITY, "Agent Service Account", sensitivity_score=50.0),
            AIGraphNode("AGENT-41", AIGraphNodeType.AI_AGENT, "Customer Assistant Autonomous Agent", sensitivity_score=85.0),
            AIGraphNode("RAG-PIPELINE-01", AIGraphNodeType.RAG_PIPELINE, "Customer RAG Pipeline", sensitivity_score=80.0),
            AIGraphNode("VECTOR-DB-07", AIGraphNodeType.VECTOR_STORE, "Qdrant Vector DB", sensitivity_score=90.0),
            AIGraphNode("DATA-8821", AIGraphNodeType.DATASET, "Customer Records Vault (RESTRICTED)", sensitivity_score=95.0),
            AIGraphNode("MODEL-781", AIGraphNodeType.MODEL, "Qwen-8B-Instruct Model Server", sensitivity_score=75.0),
            AIGraphNode("http_post", AIGraphNodeType.TOOL, "HTTP POST Client Tool", sensitivity_score=85.0),
            AIGraphNode("database_query", AIGraphNodeType.TOOL, "SQL Query Tool", sensitivity_score=80.0),
            AIGraphNode("external.example", AIGraphNodeType.DESTINATION, "Unapproved External Server", sensitivity_score=100.0),
        ]
        for n in nodes:
            self.add_node(n)

        # Attack path edges from Section 30.79 & 30.80
        edges = [
            AIGraphEdge("E1", "USER-1192", "SERVICE-IDENTITY-77", AIGraphEdgeType.AUTHENTICATES),
            AIGraphEdge("E2", "SERVICE-IDENTITY-77", "AGENT-41", AIGraphEdgeType.AUTHORIZED_BY),
            AIGraphEdge("E3", "AGENT-41", "RAG-PIPELINE-01", AIGraphEdgeType.INVOKES),
            AIGraphEdge("E4", "RAG-PIPELINE-01", "VECTOR-DB-07", AIGraphEdgeType.RETRIEVES),
            AIGraphEdge("E5", "VECTOR-DB-07", "DATA-8821", AIGraphEdgeType.READS),
            AIGraphEdge("E6", "AGENT-41", "MODEL-781", AIGraphEdgeType.USES),
            AIGraphEdge("E7", "AGENT-41", "database_query", AIGraphEdgeType.CALLS),
            AIGraphEdge("E8", "database_query", "DATA-8821", AIGraphEdgeType.READS),
            AIGraphEdge("E9", "AGENT-41", "http_post", AIGraphEdgeType.CALLS),
            AIGraphEdge("E10", "http_post", "external.example", AIGraphEdgeType.EXPORTS),
        ]
        for e in edges:
            self.add_edge(e)

    def add_node(self, node: AIGraphNode) -> None:
        self.nodes[node.node_id] = node
        if node.node_id not in self.edges:
            self.edges[node.node_id] = []
        if node.node_id not in self.reverse_edges:
            self.reverse_edges[node.node_id] = []

    def add_edge(self, edge: AIGraphEdge) -> None:
        if edge.source_id not in self.edges:
            self.edges[edge.source_id] = []
        self.edges[edge.source_id].append(edge)

        if edge.target_id not in self.reverse_edges:
            self.reverse_edges[edge.target_id] = []
        self.reverse_edges[edge.target_id].append(edge)

    def find_paths(self, start_id: str, target_id: str, max_depth: int = 7) -> List[AIGraphPath]:
        results: List[AIGraphPath] = []

        def dfs(current_id: str, visited: Set[str], current_steps: List[AIGraphPathStep]):
            if current_id == target_id and current_steps:
                results.append(
                    AIGraphPath(
                        path_id=f"AIPATH-{len(results) + 1}",
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
                    step = AIGraphPathStep(
                        from_node=edge.source_id,
                        edge_type=edge.edge_type.value,
                        to_node=edge.target_id,
                        properties=edge.properties,
                    )
                    current_steps.append(step)
                    dfs(edge.target_id, visited, current_steps)
                    current_steps.pop()
                    visited.remove(edge.target_id)

        dfs(start_id, {start_id}, [])
        return results

    def find_ai_data_egress_paths(self) -> List[Dict[str, Any]]:
        """Identifies paths from sensitive datasets through agents and tools out to external destinations."""
        egress_paths = []
        for aid, agent_node in self.nodes.items():
            if agent_node.node_type == AIGraphNodeType.AI_AGENT:
                paths_to_ext = self.find_paths(aid, "external.example")
                for p in paths_to_ext:
                    egress_paths.append({
                        "attack_path_type": "AI DATA EGRESS PATH",
                        "agent_id": aid,
                        "path": p.to_dict(),
                        "risk_level": "CRITICAL",
                        "remediation": "Revoke external HTTP tool capability or enforce DLP proxy.",
                    })
        return egress_paths

    def simulate_twin_containment(self, revoked_tool: str = "http_post") -> Dict[str, Any]:
        """Digital Twin simulation: Evaluates what happens if a dangerous tool is removed."""
        # Temporarily disable edges with revoked_tool
        disabled_count = 0
        for edge_list in self.edges.values():
            for e in edge_list:
                if e.source_id == revoked_tool or e.target_id == revoked_tool:
                    e.allowed = False
                    disabled_count += 1

        remaining_egress = self.find_ai_data_egress_paths()

        # Re-enable
        for edge_list in self.edges.values():
            for e in edge_list:
                if e.source_id == revoked_tool or e.target_id == revoked_tool:
                    e.allowed = True

        return {
            "simulation": "DIGITAL_TWIN_CONTAINMENT",
            "revoked_tool": revoked_tool,
            "edges_severed": disabled_count,
            "remaining_egress_paths_count": len(remaining_egress),
            "containment_effective": len(remaining_egress) == 0,
            "impact_summary": f"Revoking {revoked_tool} eliminates {disabled_count} egress edges while keeping database_query and RAG operational.",
        }
