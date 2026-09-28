"""
Phase 23 - Detection Coverage Matrix.
Measures multidimensional coverage across protocols, behaviors, assets, and telemetry sources.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any

@dataclass
class CoverageDimensionSummary:
    dimension: str
    categories_monitored: int
    categories_covered: int
    coverage_percentage: float
    uncovered_categories: List[str]

class DetectionCoverageEngine:
    """Computes transparent coverage dimensions without collapsing into a single naive score."""

    @classmethod
    def calculate_multidimensional_coverage(cls, active_rules: List[Any]) -> Dict[str, CoverageDimensionSummary]:
        # Protocols
        all_protocols = {"SMTP", "IMAP", "POP3", "TLS"}
        covered_protocols = set()
        for r in active_rules:
            for tag in getattr(r, "tags", []):
                if tag.upper() in all_protocols:
                    covered_protocols.add(tag.upper())
            for src in getattr(r, "data_sources", []):
                if "tls" in src.lower(): covered_protocols.add("TLS")
                if "session" in src.lower(): covered_protocols.add("SMTP")

        # Behaviors
        all_behaviors = {"TLS_DOWNGRADE", "ROGUE_CERT", "RARE_JA4", "STARTTLS_STRIP", "WEAK_CIPHER"}
        covered_behaviors = set()
        for r in active_rules:
            rid = getattr(r, "detection_id", "").upper()
            if "TLS" in rid: covered_behaviors.add("TLS_DOWNGRADE")
            if "CERT" in rid: covered_behaviors.add("ROGUE_CERT")
            if "CIPHER" in rid: covered_behaviors.add("WEAK_CIPHER")
            if "STARTTLS" in rid: covered_behaviors.add("STARTTLS_STRIP")

        # Telemetry sources
        all_sources = {"tls_events", "sessions", "certificates", "pcaps", "ja4_events"}
        covered_sources = set()
        for r in active_rules:
            for s in getattr(r, "data_sources", []):
                if s in all_sources:
                    covered_sources.add(s)

        return {
            "protocol_coverage": CoverageDimensionSummary(
                dimension="Protocol",
                categories_monitored=len(all_protocols),
                categories_covered=len(covered_protocols),
                coverage_percentage=round((len(covered_protocols) / len(all_protocols)) * 100, 1),
                uncovered_categories=list(all_protocols - covered_protocols)
            ),
            "behavior_coverage": CoverageDimensionSummary(
                dimension="Behavior",
                categories_monitored=len(all_behaviors),
                categories_covered=len(covered_behaviors),
                coverage_percentage=round((len(covered_behaviors) / len(all_behaviors)) * 100, 1),
                uncovered_categories=list(all_behaviors - covered_behaviors)
            ),
            "data_source_coverage": CoverageDimensionSummary(
                dimension="Data Source",
                categories_monitored=len(all_sources),
                categories_covered=len(covered_sources),
                coverage_percentage=round((len(covered_sources) / len(all_sources)) * 100, 1),
                uncovered_categories=list(all_sources - covered_sources)
            )
        }
