from __future__ import annotations

from typing import List

from ai_security.copilot.schemas import Citation


class CitationEngine:
    """Create evidence citations for investigation output."""

    @staticmethod
    def build_citations(references: List[str]) -> List[Citation]:
        return [
            Citation(source="tls_events", reference=item, description="Evidence associated with this investigation")
            for item in references
        ]


__all__ = ["CitationEngine", "Citation"]
