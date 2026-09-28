"""
Data Flow Graph.
Component 29.10 & 29.23: Models source-to-destination data flow topology and transfer volumes.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
import time

from data_security.flows.monitor import DataMovementEvent


@dataclass
class DataFlowEdge:
    source_asset_id: str
    destination_id: str
    total_bytes: int = 0
    total_records: int = 0
    flow_count: int = 0
    last_flow_at: float = field(default_factory=time.time)


class DataFlowGraph:
    """Aggregates observed data movement events into an enterprise data flow graph."""

    def __init__(self):
        self._flows: Dict[str, DataFlowEdge] = {}  # key: f"{source}->{destination}"

    def update_with_event(self, event: DataMovementEvent) -> None:
        key = f"{event.source_asset_id}->{event.destination_id}"
        if key not in self._flows:
            self._flows[key] = DataFlowEdge(
                source_asset_id=event.source_asset_id,
                destination_id=event.destination_id,
            )
        flow = self._flows[key]
        flow.total_bytes += event.bytes_transferred
        flow.total_records += event.record_count
        flow.flow_count += 1
        flow.last_flow_at = event.timestamp

    def get_flows_for_asset(self, asset_id: str) -> List[Dict[str, Any]]:
        results = []
        for key, edge in self._flows.items():
            if edge.source_asset_id == asset_id or edge.destination_id == asset_id:
                results.append({
                    "flow_key": key,
                    "source": edge.source_asset_id,
                    "destination": edge.destination_id,
                    "total_bytes": edge.total_bytes,
                    "total_records": edge.total_records,
                    "flow_count": edge.flow_count,
                    "last_flow_at": edge.last_flow_at,
                })
        return results

    def list_all_flows(self) -> List[Dict[str, Any]]:
        return [
            {
                "source": edge.source_asset_id,
                "destination": edge.destination_id,
                "total_bytes": edge.total_bytes,
                "total_records": edge.total_records,
                "flow_count": edge.flow_count,
            }
            for edge in self._flows.values()
        ]
