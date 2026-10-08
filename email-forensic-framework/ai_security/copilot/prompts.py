from __future__ import annotations

from typing import Dict


COPILOT_PROMPTS: Dict[str, str] = {
    "investigate": "Investigate the entity, collect related alerts, sessions, and TLS evidence, then explain the likely attack path.",
    "hunt": "Generate a threat hunt for suspicious behavior, validate the query, and summarize the results with evidence-backed findings.",
    "recommend": "Recommend a safe response, check policy constraints, and mention approval and rollback requirements.",
}


def build_investigation_prompt(query: str) -> str:
    return f"You are Garuda AI SOC Copilot. Investigate: {query}. Use structured evidence and never fabricate tool execution or telemetry."


__all__ = ["COPILOT_PROMPTS", "build_investigation_prompt"]
