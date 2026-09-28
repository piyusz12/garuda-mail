"""
Phase 23 - Hunt Query Planner.
Translates HQL AST into an optimized execution strategy across Lakehouse layers.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from .dsl import HuntQueryAST, HuntQueryCondition

@dataclass
class ExecutionPlan:
    plan_id: str
    hunt_name: str
    target_layers: List[str]  # e.g., ["SILVER", "GOLD"]
    target_entity: str       # e.g., "SESSION", "TLS_EVENT"
    time_cutoff: Optional[datetime] = None
    event_filters: List[HuntQueryCondition] = field(default_factory=list)
    historical_filters: List[HuntQueryCondition] = field(default_factory=list)
    estimated_cost_units: int = 10


class HuntQueryPlanner:
    """Optimizes and constructs execution plans for HQL queries."""

    @classmethod
    def create_plan(cls, ast: HuntQueryAST, reference_time: Optional[datetime] = None) -> ExecutionPlan:
        ref_time = reference_time or datetime.now(timezone.utc)
        time_cutoff = None

        if ast.within_window:
            unit = ast.within_window[-1]
            val = int(ast.within_window[:-1])
            if unit == "d":
                time_cutoff = ref_time - timedelta(days=val)
            elif unit == "h":
                time_cutoff = ref_time - timedelta(hours=val)
            elif unit == "m":
                time_cutoff = ref_time - timedelta(minutes=val)
            elif unit == "s":
                time_cutoff = ref_time - timedelta(seconds=val)

        # Map source entity to Lakehouse entity type
        entity_map = {
            "tls_events": ("SILVER", "SESSION"),
            "sessions": ("SILVER", "SESSION"),
            "certificates": ("SILVER", "CERTIFICATE"),
            "postures": ("GOLD", "ASSET_POSTURE"),
            "findings": ("GOLD", "FINDING")
        }
        layer, lake_entity = entity_map.get(ast.source_entity, ("SILVER", ast.source_entity.upper()))

        cost = 10
        if ast.within_window and "d" in ast.within_window and int(ast.within_window[:-1]) > 30:
            cost += 40  # Deep historical query cost
        if ast.historical_conditions:
            cost += 25  # Cross-table join cost

        import uuid
        return ExecutionPlan(
            plan_id=f"PLAN-{uuid.uuid4().hex[:6].upper()}",
            hunt_name=ast.hunt_name,
            target_layers=[layer],
            target_entity=lake_entity,
            time_cutoff=time_cutoff,
            event_filters=ast.conditions,
            historical_filters=ast.historical_conditions,
            estimated_cost_units=cost
        )
