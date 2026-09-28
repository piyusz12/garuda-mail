"""
Change Impact Analyzer & Control Dependency Graph.
Calculates the minimal affected scenario subset when a sensor, rule, parser, or playbook changes.
"""
from typing import Dict, List, Set, Optional, Any


class ChangeImpactAnalyzer:
    """Maps platform changes directly to affected validation scenarios to avoid redundant full-suite runs."""

    def __init__(self):
        # Component -> Set of Scenario IDs
        self._dependency_map: Dict[str, Set[str]] = {
            "tls_sensor": {"SCN-101", "SCN-102"},
            "cert_parser": {"SCN-102"},
            "ja4_engine": {"SCN-101"},
            "starttls_handler": {"SCN-103"},
            "pqc_hybrid_kex": {"SCN-104"},
            "DET-TLS-001": {"SCN-101"},
            "CERT-CHANGE-001": {"SCN-102"},
            "STARTTLS-STRIP-001": {"SCN-103"},
            "PQC-DOWNGRADE-001": {"SCN-104"},
            "playbook_rotate_cert": {"SCN-102"},
            "playbook_isolate_host": {"SCN-101"},
        }

    def register_dependency(self, component_name: str, scenario_id: str) -> None:
        if component_name not in self._dependency_map:
            self._dependency_map[component_name] = set()
        self._dependency_map[component_name].add(scenario_id)

    def calculate_affected_scenarios(self, changed_components: List[str]) -> List[str]:
        """Returns the deduplicated list of scenarios requiring re-execution."""
        affected = set()
        for comp in changed_components:
            if comp in self._dependency_map:
                affected.update(self._dependency_map[comp])
            else:
                # Fuzzy matching
                for key, scns in self._dependency_map.items():
                    if comp.lower() in key.lower():
                        affected.update(scns)

        return sorted(list(affected))
