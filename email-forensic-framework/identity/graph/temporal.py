"""
Temporal Identity Graph & Identity Time Machine.
Reconstructs point-in-time identity relationships, device ownership, and historical access paths.
"""
from typing import Dict, List, Optional, Any, Set
import time
import uuid

from .nodes import IdentityNode, IdentityNodeType
from .edges import IdentityEdge, IdentityEdgeType


class TemporalIdentityGraph:
    """Graph database abstraction tracking evolving identity relationships over time."""

    def __init__(self):
        self._nodes: Dict[str, IdentityNode] = {}
        self._edges: List[IdentityEdge] = []
        self._load_seed_graph()

    def _load_seed_graph(self):
        # 1. Nodes
        nodes = [
            IdentityNode("ID-1192", IdentityNodeType.PERSON, "John Smith", {"department": "Security Operations"}),
            IdentityNode("ID-2044", IdentityNodeType.PERSON, "Alice Chen", {"department": "Network Infrastructure"}),
            IdentityNode("DEVICE-44", IdentityNodeType.DEVICE, "soc-laptop-44", {"managed": True}),
            IdentityNode("DEVICE-91", IdentityNodeType.DEVICE, "infra-box-91", {"managed": True}),
            IdentityNode("MTA-07", IdentityNodeType.SERVICE, "Primary Edge Mail Gateway", {"classification": "CRITICAL"}),
            IdentityNode("FORENSIC-API", IdentityNodeType.SERVICE, "Forensic Investigation Console", {"classification": "CRITICAL"}),
            IdentityNode("GROUP-SECOPS", IdentityNodeType.GROUP, "security-ops", {}),
            IdentityNode("GROUP-MTAADMINS", IdentityNodeType.GROUP, "mta-admins", {}),
            IdentityNode("ROLE-SOCADMIN", IdentityNodeType.ROLE, "SOC_ADMIN", {}),
            IdentityNode("CERT-882", IdentityNodeType.CERTIFICATE, "CERT-2026-PRIMARY", {}),
        ]
        for n in nodes:
            self._nodes[n.node_id] = n

        # 2. Historical & Active Edges
        t_base = time.time() - (86400 * 90)  # 90 days ago
        edges = [
            IdentityEdge("e1", "ID-1192", "DEVICE-44", IdentityEdgeType.OWNS, valid_from=t_base),
            IdentityEdge("e2", "ID-1192", "GROUP-SECOPS", IdentityEdgeType.MEMBER_OF, valid_from=t_base),
            IdentityEdge("e3", "GROUP-SECOPS", "ROLE-SOCADMIN", IdentityEdgeType.HAS_ROLE, valid_from=t_base),
            IdentityEdge("e4", "ID-1192", "FORENSIC-API", IdentityEdgeType.USES, valid_from=t_base),
            IdentityEdge("e5", "ID-2044", "DEVICE-91", IdentityEdgeType.OWNS, valid_from=t_base),
            IdentityEdge("e6", "ID-2044", "GROUP-MTAADMINS", IdentityEdgeType.MEMBER_OF, valid_from=t_base),
            IdentityEdge("e7", "ID-2044", "MTA-07", IdentityEdgeType.USES, valid_from=t_base),
            IdentityEdge("e8", "MTA-07", "CERT-882", IdentityEdgeType.PRESENTS, valid_from=t_base),
            # East-West microservice relationship
            IdentityEdge("e9", "FORENSIC-API", "MTA-07", IdentityEdgeType.COMMUNICATES_WITH, valid_from=t_base),
        ]
        self._edges.extend(edges)

    def add_node(self, node: IdentityNode) -> None:
        self._nodes[node.node_id] = node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: IdentityEdgeType,
        valid_from: Optional[float] = None,
        valid_to: Optional[float] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> IdentityEdge:
        edge = IdentityEdge(
            edge_id=f"e-{uuid.uuid4().hex[:8]}",
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            valid_from=valid_from or time.time(),
            valid_to=valid_to,
            properties=properties or {},
        )
        self._edges.append(edge)
        return edge

    def get_node(self, node_id: str) -> Optional[IdentityNode]:
        return self._nodes.get(node_id)

    def get_neighbors(
        self,
        node_id: str,
        edge_type: Optional[IdentityEdgeType] = None,
        at_timestamp: Optional[float] = None,
    ) -> List[IdentityNode]:
        ts = at_timestamp or time.time()
        neighbors = []

        for e in self._edges:
            if not e.is_active_at(ts):
                continue

            if edge_type and e.edge_type != edge_type:
                continue

            if e.source_id == node_id and e.target_id in self._nodes:
                neighbors.append(self._nodes[e.target_id])
            elif e.target_id == node_id and e.source_id in self._nodes:
                neighbors.append(self._nodes[e.source_id])

        return neighbors

    def point_in_time_query(self, entity_id: str, timestamp: float) -> Dict[str, Any]:
        """Identity Time Machine: Reconstructs state of an entity at an exact timestamp."""
        active_edges = [e for e in self._edges if e.is_active_at(timestamp) and (e.source_id == entity_id or e.target_id == entity_id)]
        related_nodes = set()
        for e in active_edges:
            related_nodes.add(e.source_id)
            related_nodes.add(e.target_id)

        node = self._nodes.get(entity_id)
        return {
            "entity_id": entity_id,
            "timestamp": timestamp,
            "entity": node.to_dict() if node else None,
            "active_relationships": [e.to_dict() for e in active_edges],
            "related_entities": [self._nodes[nid].to_dict() for nid in related_nodes if nid in self._nodes],
        }

    def trace_access_path(self, subject_id: str, resource_id: str) -> List[str]:
        """Traces the relationship chain from subject to resource."""
        # Simple BFS path search
        visited = set()
        queue = [[subject_id]]

        while queue:
            path = queue.pop(0)
            current = path[-1]

            if current == resource_id:
                return path

            if current not in visited:
                visited.add(current)
                neighbors = [n.node_id for n in self.get_neighbors(current)]
                for neighbor in neighbors:
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)

        return []
