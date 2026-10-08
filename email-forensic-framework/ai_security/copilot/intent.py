from __future__ import annotations

import re
from typing import List

from ai_security.copilot.schemas import InvestigationIntent


class IntentClassifier:
    """Map natural-language analyst requests to investigation intents."""

    @staticmethod
    def classify(query: str) -> InvestigationIntent:
        text = (query or "").strip().lower()
        if not text:
            return InvestigationIntent.INVESTIGATE

        if any(k in text for k in ["investigate", "suspicious", "activity", "incident", "alert", "connection", "malicious"]):
            return InvestigationIntent.INVESTIGATE
        if any(k in text for k in ["why", "explain", "reason", "root cause", "what caused", "how did"]):
            return InvestigationIntent.EXPLAIN
        if any(k in text for k in ["hunt", "rare", "find similar", "look for", "search for", "associated with"]):
            return InvestigationIntent.HUNT
        if any(k in text for k in ["summary", "summarize", "overview", "what happened"]):
            return InvestigationIntent.SUMMARIZE
        if any(k in text for k in ["compare", "similar incidents", "historical", "prior cases"]):
            return InvestigationIntent.COMPARE
        if any(k in text for k in ["recommend", "what should i do", "should i", "next step", "response"]):
            return InvestigationIntent.RECOMMEND
        if any(k in text for k in ["simulate", "model outcome", "what if", "impact if"]):
            return InvestigationIntent.SIMULATE
        if any(k in text for k in ["report", "write up", "final report", "briefing"]):
            return InvestigationIntent.REPORT
        if any(k in text for k in ["search", "lookup", "find", "query"]):
            return InvestigationIntent.SEARCH
        return InvestigationIntent.INVESTIGATE

    @staticmethod
    def resolve_entity(query: str) -> str:
        match = re.search(r"\b[A-Z]+-\d+\b|\b[A-Z]{2,}-[A-Z0-9-]+\b", query, flags=re.IGNORECASE)
        if match:
            return match.group(0).upper()
        if "mta" in query.lower():
            m = re.search(r"mta[-_ ]?(\d+)", query.lower())
            if m:
                return f"MTA-{m.group(1)}"
        return "UNKNOWN_ENTITY"

    @staticmethod
    def extract_time_range(query: str) -> str:
        text = query.lower()
        if "90d" in text or "last 90" in text:
            return "90d"
        if "30d" in text or "last 30" in text:
            return "30d"
        if "7d" in text or "last 7" in text:
            return "7d"
        return "90d"


def classify_intent(query: str) -> InvestigationIntent:
    return IntentClassifier.classify(query)


def resolve_entity(query: str) -> str:
    return IntentClassifier.resolve_entity(query)


def extract_time_range(query: str) -> str:
    return IntentClassifier.extract_time_range(query)


__all__ = [
    "IntentClassifier",
    "InvestigationIntent",
    "classify_intent",
    "resolve_entity",
    "extract_time_range",
]
