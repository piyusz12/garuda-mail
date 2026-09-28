"""
Phase 24 — Blast Radius Analysis (Component 17, 23)
Traverses the forensic dependency graph (Asset -> Service -> Certificate -> Client -> Relays)
to calculate potential operational exposure before risky remediation actions.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Any, Optional


@dataclass
class BlastRadiusReport:
    target_assets: List[str]
    total_enterprise_assets: int
    blast_radius_ratio: float
    affected_services: List[str]
    dependent_relays: List[str]
    external_client_groups_impacted: int
    critical_dependencies_count: int
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    safe_for_automated_execution: bool
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BlastRadiusCalculator:
    """Traverses dependency graphs to prevent unexpected service outages during remediation."""

    def __init__(self, dependency_graph: Optional[Dict[str, Dict[str, Any]]] = None):
        # Default enterprise topology graph
        self.dependency_graph = dependency_graph or {
            "MTA-01": {"services": ["smtp-out"], "downstream": ["MTA-02"], "clients": 12, "critical": False},
            "MTA-02": {"services": ["smtp-in", "mx1"], "downstream": ["MTA-03"], "clients": 45, "critical": False},
            "MTA-03": {"services": ["submission"], "downstream": [], "clients": 80, "critical": False},
            "MTA-04": {"services": ["executive-mail", "smtp-tls"], "downstream": ["MTA-01"], "clients": 15, "critical": True},
            "MTA-07": {"services": ["partner-relay", "cross-border"], "downstream": ["MTA-01", "MTA-04"], "clients": 24, "critical": True},
            "MTA-08": {"services": ["bulk-mailer"], "downstream": [], "clients": 6, "critical": False},
            "MTA-11": {"services": ["staging-relay"], "downstream": [], "clients": 2, "critical": False},
        }

    def calculate_blast_radius(self, target_assets: List[str], action_type: str = "DISABLE_TLS11") -> BlastRadiusReport:
        visited_assets: Set[str] = set(target_assets)
        affected_services: Set[str] = set()
        dependent_relays: Set[str] = set()
        client_impact_count = 0
        critical_deps = 0

        # Traversal queue
        queue = list(target_assets)
        while queue:
            current = queue.pop(0)
            meta = self.dependency_graph.get(current, {"services": [], "downstream": [], "clients": 0, "critical": False})
            for s in meta.get("services", []):
                affected_services.add(s)
            client_impact_count += meta.get("clients", 0)
            if meta.get("critical", False):
                critical_deps += 1

            for down in meta.get("downstream", []):
                if down not in visited_assets:
                    visited_assets.add(down)
                    dependent_relays.add(down)
                    queue.append(down)

        total_assets = max(len(self.dependency_graph), 1)
        radius_ratio = min(1.0, len(visited_assets) / total_assets)

        if radius_ratio > 0.4 or critical_deps > 1:
            risk = "CRITICAL"
        elif radius_ratio > 0.25 or critical_deps > 0:
            risk = "HIGH"
        elif radius_ratio > 0.1:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        safe_auto = (risk in ["LOW", "MEDIUM"]) and (critical_deps == 0)

        summary = (
            f"Blast radius affects {len(visited_assets)} assets ({radius_ratio*100:.0f}% of enterprise). "
            f"Estimated {client_impact_count} client groups impacted, {critical_deps} critical dependencies."
        )

        return BlastRadiusReport(
            target_assets=target_assets,
            total_enterprise_assets=total_assets,
            blast_radius_ratio=round(radius_ratio, 2),
            affected_services=list(affected_services),
            dependent_relays=list(dependent_relays),
            external_client_groups_impacted=client_impact_count,
            critical_dependencies_count=critical_deps,
            risk_level=risk,
            safe_for_automated_execution=safe_auto,
            summary=summary
        )
