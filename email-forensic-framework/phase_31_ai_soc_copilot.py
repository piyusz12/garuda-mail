"""Phase 31: Garuda AI SOC Copilot.

This module exposes the investigation-oriented copilot that sits on top of the
existing Garuda security engines and evidence graph. It intentionally keeps the
control-plane security checks in place while enabling evidence-first analyst
investigation workflows.
"""

from ai_security.copilot import AIInvestigationCopilot, CopilotQuery

__all__ = ["AIInvestigationCopilot", "CopilotQuery"]
