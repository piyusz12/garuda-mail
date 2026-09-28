"""
Zero Trust Policy Representation & DSL Parser.
Parses declarative policies into structured Policy objects.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum
import json
import re


class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"
    RESTRICT = "RESTRICT"


@dataclass
class PolicyCondition:
    attribute: str  # e.g., device.managed, session.risk, subject.group, resource.classification
    operator: str   # ==, !=, in, not_in, <=, >=
    value: Any

    def evaluate(self, context_dict: Dict[str, Any]) -> bool:
        # Resolve nested key e.g. device.managed -> context_dict['device']['managed'] or context_dict['device.managed']
        val = None
        if self.attribute in context_dict:
            val = context_dict[self.attribute]
        elif "." in self.attribute:
            parts = self.attribute.split(".")
            curr = context_dict
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    curr = None
                    break
            val = curr

        if self.operator == "==":
            return val == self.value
        elif self.operator == "!=":
            return val != self.value
        elif self.operator == "in":
            return val in self.value if hasattr(self.value, "__contains__") else False
        elif self.operator == "not_in":
            return val not in self.value if hasattr(self.value, "__contains__") else True
        elif self.operator == "<=":
            # Mapping string hierarchy for classification
            ranks = {"PUBLIC": 1, "INTERNAL": 2, "SENSITIVE": 3, "CRITICAL": 4}
            v_rank = ranks.get(str(val).upper(), 99)
            req_rank = ranks.get(str(self.value).upper(), 99)
            return v_rank <= req_rank
        elif self.operator == ">=":
            ranks = {"PUBLIC": 1, "INTERNAL": 2, "SENSITIVE": 3, "CRITICAL": 4}
            v_rank = ranks.get(str(val).upper(), 99)
            req_rank = ranks.get(str(self.value).upper(), 99)
            return v_rank >= req_rank
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attribute": self.attribute,
            "operator": self.operator,
            "value": self.value,
        }


@dataclass
class ZeroTrustPolicy:
    policy_id: str
    name: str
    effect: PolicyEffect
    description: str = ""
    target_services: List[str] = field(default_factory=lambda: ["*"])
    target_actions: List[str] = field(default_factory=lambda: ["*"])
    conditions: List[PolicyCondition] = field(default_factory=list)
    priority: int = 100  # Lower number = higher precedence
    version: str = "1.0.0"
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "effect": self.effect.value if isinstance(self.effect, PolicyEffect) else self.effect,
            "description": self.description,
            "target_services": self.target_services,
            "target_actions": self.target_actions,
            "conditions": [c.to_dict() for c in self.conditions],
            "priority": self.priority,
            "version": self.version,
            "is_active": self.is_active,
        }


class PolicyDSLParser:
    """Parses text-based Policy DSL or JSON into ZeroTrustPolicy objects."""

    @staticmethod
    def parse_dict(data: Dict[str, Any]) -> ZeroTrustPolicy:
        effect_str = data.get("effect", "ALLOW").upper()
        effect = PolicyEffect[effect_str] if effect_str in PolicyEffect.__members__ else PolicyEffect.ALLOW

        conditions = []
        for c in data.get("conditions", []):
            if isinstance(c, dict):
                conditions.append(PolicyCondition(
                    attribute=c["attribute"],
                    operator=c.get("operator", "=="),
                    value=c["value"],
                ))
            elif isinstance(c, PolicyCondition):
                conditions.append(c)

        return ZeroTrustPolicy(
            policy_id=data["policy_id"],
            name=data.get("name", data["policy_id"]),
            effect=effect,
            description=data.get("description", ""),
            target_services=data.get("target_services", ["*"]),
            target_actions=data.get("target_actions", ["*"]),
            conditions=conditions,
            priority=data.get("priority", 100),
            version=data.get("version", "1.0.0"),
            is_active=data.get("is_active", True),
        )

    @classmethod
    def parse_dsl(cls, text: str, policy_id: str, name: str) -> ZeroTrustPolicy:
        """
        Parses human-readable DSL syntax:
        ALLOW
        WHEN
          subject.group == "security-ops"
          AND device.managed == true
        """
        lines = [line.strip() for line in text.strip().splitlines() if line.strip() and not line.strip().startswith("#")]
        if not lines:
            raise ValueError("Empty DSL text")

        effect_line = lines[0].upper()
        if effect_line.startswith("ALLOW"):
            effect = PolicyEffect.ALLOW
        elif effect_line.startswith("DENY"):
            effect = PolicyEffect.DENY
        elif effect_line.startswith("STEP_UP") or effect_line.startswith("STEP-UP"):
            effect = PolicyEffect.STEP_UP
        elif effect_line.startswith("RESTRICT"):
            effect = PolicyEffect.RESTRICT
        else:
            effect = PolicyEffect.ALLOW

        conditions = []
        # Search for conditions after WHEN
        cond_lines = []
        in_when = False
        for l in lines[1:]:
            if l.upper() == "WHEN":
                in_when = True
                continue
            if in_when:
                # Remove leading 'AND ' if present
                clean_l = re.sub(r"^AND\s+", "", l, flags=re.IGNORECASE)
                cond_lines.append(clean_l)

        for cl in cond_lines:
            # Match: attribute operator value
            match = re.match(r"^([\w\.]+)\s*(==|!=|in|not_in|<=|>=)\s*(.+)$", cl)
            if match:
                attr, op, raw_val = match.groups()
                # Parse value: boolean, string, or int
                val_str = raw_val.strip()
                if val_str.lower() == "true":
                    val = True
                elif val_str.lower() == "false":
                    val = False
                elif val_str.startswith('"') and val_str.endswith('"'):
                    val = val_str[1:-1]
                elif val_str.startswith("'") and val_str.endswith("'"):
                    val = val_str[1:-1]
                elif val_str.isdigit():
                    val = int(val_str)
                else:
                    val = val_str
                conditions.append(PolicyCondition(attribute=attr, operator=op, value=val))

        return ZeroTrustPolicy(
            policy_id=policy_id,
            name=name,
            effect=effect,
            conditions=conditions,
        )
