"""Garuda Enterprise AI Security - Detection Engineering Engine.
Phase 30 Section 30.83: Evaluates streaming and batch events against AI detection rules.
"""
from typing import Dict, List, Optional, Any
from ai_security.events import AISecurityEvent, AISecurityEventBus
from ai_security.detections.rules import (
    AIDetectionRule,
    AIDetectionAlert,
    RuleAI001_RestrictedDataExternalModel,
    RuleAI002_AgentUnauthorizedTool,
    RuleAI003_CrossTenantRetrieval,
    RuleAI004_ModelIntegrityMismatch,
    RuleAI005_AgentToolLoopAnomaly,
    RuleAI006_UnexpectedModelEgress,
    RuleAI007_SecretDetectedInPrompt,
    RuleAI008_RestrictedDocUnauthorizedAgent,
)


class AIDetectionEngine:
    """Detection engine managing versioned AI rules AI-001 through AI-008."""

    def __init__(self, event_bus: Optional[AISecurityEventBus] = None):
        self.event_bus = event_bus or AISecurityEventBus.get_instance()
        self._rules: Dict[str, AIDetectionRule] = {}
        self._alerts: List[AIDetectionAlert] = []
        self.register_defaults()

    def register_defaults(self):
        self.register_rule(RuleAI001_RestrictedDataExternalModel())
        self.register_rule(RuleAI002_AgentUnauthorizedTool())
        self.register_rule(RuleAI003_CrossTenantRetrieval())
        self.register_rule(RuleAI004_ModelIntegrityMismatch())
        self.register_rule(RuleAI005_AgentToolLoopAnomaly())
        self.register_rule(RuleAI006_UnexpectedModelEgress())
        self.register_rule(RuleAI007_SecretDetectedInPrompt())
        self.register_rule(RuleAI008_RestrictedDocUnauthorizedAgent())

    def register_rule(self, rule: AIDetectionRule):
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[AIDetectionRule]:
        return self._rules.get(rule_id)

    def list_rules(self) -> List[AIDetectionRule]:
        return list(self._rules.values())

    def evaluate_event(self, event: AISecurityEvent) -> List[AIDetectionAlert]:
        """Evaluate a single event against all active rules."""
        generated_alerts = []
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            alert = rule.evaluate(event)
            if alert:
                generated_alerts.append(alert)
                self._alerts.append(alert)
        return generated_alerts

    def evaluate_events(self, events: List[AISecurityEvent]) -> List[AIDetectionAlert]:
        """Batch evaluate a list of events."""
        all_alerts = []
        for ev in events:
            alerts = self.evaluate_event(ev)
            all_alerts.extend(alerts)
        return all_alerts

    def list_alerts(self, severity: Optional[str] = None) -> List[AIDetectionAlert]:
        if severity:
            s_up = severity.upper()
            return [a for a in self._alerts if a.severity == s_up]
        return list(self._alerts)

    def clear_alerts(self):
        self._alerts.clear()
