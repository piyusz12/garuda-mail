"""
Cloud Virtual Networks, Subnets, and Security Groups.
Component 28 & 29: Cloud network topology, micro-segmentation, and security group filtering.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from cloud.inventory.accounts import CloudProvider


class RuleDirection(str, Enum):
    INGRESS = "INGRESS"
    EGRESS = "EGRESS"


@dataclass
class SecurityGroupRule:
    rule_id: str
    direction: RuleDirection
    protocol: str  # TCP, UDP, ICMP, ALL
    from_port: int
    to_port: int
    cidr_block: str = "0.0.0.0/0"  # e.g., "0.0.0.0/0", "10.0.0.0/16"
    cidr: Optional[str] = None
    description: str = ""

    def __post_init__(self):
        if self.cidr and (not self.cidr_block or self.cidr_block == "0.0.0.0/0"):
            self.cidr_block = self.cidr

    def is_unrestricted_ingress(self) -> bool:
        return self.direction == RuleDirection.INGRESS and self.cidr_block in ("0.0.0.0/0", "::/0")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "direction": self.direction.value if isinstance(self.direction, RuleDirection) else self.direction,
            "protocol": self.protocol,
            "from_port": self.from_port,
            "to_port": self.to_port,
            "cidr_block": self.cidr_block,
            "is_unrestricted": self.is_unrestricted_ingress(),
        }


@dataclass
class SecurityGroup:
    group_id: str = "SG-DEFAULT"
    group_name: str = "default-sg"
    vpc_id: str = "vpc-default"
    sg_id: Optional[str] = None
    name: Optional[str] = None
    rules: List[SecurityGroupRule] = field(default_factory=list)

    def __post_init__(self):
        if self.sg_id:
            self.group_id = self.sg_id
        if self.name:
            self.group_name = self.name

    def has_exposed_port(self, port: int) -> bool:
        for r in self.rules:
            if r.is_unrestricted_ingress() and r.from_port <= port <= r.to_port:
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "vpc_id": self.vpc_id,
            "rules_count": len(self.rules),
            "rules": [r.to_dict() for r in self.rules],
        }


@dataclass
class VPCNetwork:
    vpc_id: str
    vpc_name: str
    provider: CloudProvider
    account_id: str
    cidr_block: str
    security_groups: Dict[str, SecurityGroup] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vpc_id": self.vpc_id,
            "vpc_name": self.vpc_name,
            "cidr_block": self.cidr_block,
            "security_groups_count": len(self.security_groups),
        }
