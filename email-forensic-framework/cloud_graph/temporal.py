"""
Temporal Cloud Graph and Historical Topology Tracking.
Components 47, 52, 54: Captures point-in-time graph snapshots and compares structural topology evolution.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
import time
import copy

from cloud_graph.nodes import CloudNode
from cloud_graph.edges import CloudEdge


@dataclass
class GraphSnapshot:
    snapshot_id: str
    label: str
    nodes: Dict[str, Dict[str, Any]]
    edges: List[Dict[str, Any]]
    timestamp: float = field(default_factory=time.time)


class TemporalCloudGraph:
    """Maintains time-series snapshots of the cloud-native graph topology."""

    def __init__(self):
        self.snapshots: Dict[str, GraphSnapshot] = {}

    def capture_snapshot(
        self,
        snapshot_id: str,
        label: str,
        nodes: Dict[str, CloudNode],
        edges: Dict[str, List[CloudEdge]],
    ) -> GraphSnapshot:
        node_dicts = {nid: n.to_dict() for nid, n in nodes.items()}
        edge_dicts = []
        for src, elist in edges.items():
            for e in elist:
                edge_dicts.append(e.to_dict())

        snap = GraphSnapshot(
            snapshot_id=snapshot_id,
            label=label,
            nodes=node_dicts,
            edges=edge_dicts,
        )
        self.snapshots[snapshot_id] = snap
        return snap

    def diff_snapshots(self, snap_id_old: str, snap_id_new: str) -> Dict[str, Any]:
        """Calculates topological differences between two point-in-time snapshots."""
        old_snap = self.snapshots.get(snap_id_old)
        new_snap = self.snapshots.get(snap_id_new)
        if not old_snap or not new_snap:
            return {"error": "Snapshot not found"}

        old_nodes = set(old_snap.nodes.keys())
        new_nodes = set(new_snap.nodes.keys())

        added_nodes = list(new_nodes - old_nodes)
        removed_nodes = list(old_nodes - new_nodes)

        old_edges = {(e["source_id"], e["target_id"], e["edge_type"]) for e in old_snap.edges}
        new_edges = {(e["source_id"], e["target_id"], e["edge_type"]) for e in new_snap.edges}

        added_edges = [{"source": s, "target": t, "type": ty} for (s, t, ty) in (new_edges - old_edges)]
        removed_edges = [{"source": s, "target": t, "type": ty} for (s, t, ty) in (old_edges - new_edges)]

        return {
            "from_snapshot": snap_id_old,
            "to_snapshot": snap_id_new,
            "added_nodes": added_nodes,
            "removed_nodes": removed_nodes,
            "added_edges": added_edges,
            "removed_edges": removed_edges,
            "has_topology_drift": bool(added_nodes or removed_nodes or added_edges or removed_edges),
        }
