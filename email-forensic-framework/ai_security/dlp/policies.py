"""AI DLP Policy Definitions.
Components 30.13 & 30.90: Defines multi-condition rules binding classification, model egress, and tool channels.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

from data_security.inventory.normalization import ClassificationLevel
from ai_security.dlp.decisions import AIDLPAction


@dataclass
class AIDLPPolicy:
    policy_id: str
    name: str
    target_classifications: List[ClassificationLevel]
    action: AIDLPAction
    prohibit_external_model: bool = True
    prohibit_external_tool: bool = True
    max_record_threshold: int = 1000

    def evaluate(self, event_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """Returns (is_violated, reason)."""
        raw_class = event_dict.get("classification", "INTERNAL")
        if isinstance(raw_class, str):
            classification = ClassificationLevel(raw_class.upper())
        else:
            classification = raw_class

        if classification not in self.target_classifications:
            return False, "Classification not in policy scope."

        is_external_model = event_dict.get("is_external_model", False) or (event_dict.get("is_external", False) and not event_dict.get("is_external_tool", False))
        is_external_tool = event_dict.get("is_external_destination", False) or event_dict.get("is_external_tool", False) or (event_dict.get("is_external", False) and event_dict.get("is_external_tool", False))
        if event_dict.get("is_external", False) and not is_external_model and not is_external_tool:
            is_external_model = True
            is_external_tool = True
        records = event_dict.get("record_count", 1)

        if self.prohibit_external_model and is_external_model:
            return True, f"Policy {self.policy_id}: Transfer of {classification.value} data to external model is prohibited."

        if self.prohibit_external_tool and is_external_tool:
            dest = event_dict.get("destination", "external endpoint")
            return True, f"Policy {self.policy_id}: Egress of {classification.value} data via external tool/endpoint {dest} is prohibited."

        if records > self.max_record_threshold:
            return True, f"Policy {self.policy_id}: Data transfer exceeds permitted record volume threshold ({records} > {self.max_record_threshold})."

        return False, "Compliant."
