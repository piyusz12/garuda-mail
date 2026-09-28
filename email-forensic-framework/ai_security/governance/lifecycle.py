"""Garuda Enterprise AI Security - Governance & Model Deprecation.
Phase 30 Sections 30.43 & 30.44: Enterprise AI governance metadata,
compliance tracking, and model lifecycle deprecation governance.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time

from ai_security.inventory.assets import ModelLifecycleStatus


class AIRiskTier(str, Enum):
    TIER_1_CRITICAL = "TIER_1_CRITICAL"
    TIER_2_HIGH = "TIER_2_HIGH"
    TIER_3_MEDIUM = "TIER_3_MEDIUM"
    TIER_4_LOW = "TIER_4_LOW"


@dataclass
class AIGovernanceRecord:
    asset_id: str
    owner: str
    business_purpose: str
    risk_tier: AIRiskTier
    approved_environments: List[str]
    approved_data_classifications: List[str]
    review_frequency_days: int = 90
    last_reviewed_at: float = field(default_factory=time.time)
    compliance_frameworks: List[str] = field(default_factory=lambda: ["NIST_AI_RMF", "EU_AI_ACT"])
    exceptions: List[Dict[str, Any]] = field(default_factory=list)

    def is_review_overdue(self) -> bool:
        overdue_threshold = self.last_reviewed_at + (self.review_frequency_days * 86400)
        return time.time() > overdue_threshold

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "owner": self.owner,
            "business_purpose": self.business_purpose,
            "risk_tier": self.risk_tier.value,
            "approved_environments": self.approved_environments,
            "approved_data_classifications": self.approved_data_classifications,
            "review_frequency_days": self.review_frequency_days,
            "last_reviewed_at": self.last_reviewed_at,
            "is_review_overdue": self.is_review_overdue(),
            "compliance_frameworks": self.compliance_frameworks,
            "exceptions": self.exceptions,
        }


@dataclass
class ModelDeprecationReport:
    model_id: str
    status: ModelLifecycleStatus
    is_deprecated_or_blocked: bool
    dependent_agents: List[str]
    dependent_applications: List[str]
    recommended_replacement_model: Optional[str] = None
    migration_deadline: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "status": self.status.value,
            "is_deprecated_or_blocked": self.is_deprecated_or_blocked,
            "dependent_agents": self.dependent_agents,
            "dependent_applications": self.dependent_applications,
            "recommended_replacement_model": self.recommended_replacement_model,
            "migration_deadline": self.migration_deadline,
        }


class AIGovernanceManager:
    """Enterprise governance registry enforcing lifecycle and compliance."""

    def __init__(self):
        self._governance: Dict[str, AIGovernanceRecord] = {}
        self._model_dependencies: Dict[str, Dict[str, List[str]]] = {}
        self.register_default_governance()

    def register_default_governance(self):
        self._governance["MODEL-781"] = AIGovernanceRecord(
            asset_id="MODEL-781",
            owner="secops-ai-team@garuda.internal",
            business_purpose="Internal threat triage & log summarization",
            risk_tier=AIRiskTier.TIER_2_HIGH,
            approved_environments=["PRODUCTION", "STAGING"],
            approved_data_classifications=["INTERNAL", "CONFIDENTIAL"],
        )
        self._governance["AGENT-41"] = AIGovernanceRecord(
            asset_id="AGENT-41",
            owner="customer-engineering@garuda.internal",
            business_purpose="Autonomous customer support and CRM lookup",
            risk_tier=AIRiskTier.TIER_2_HIGH,
            approved_environments=["PRODUCTION"],
            approved_data_classifications=["INTERNAL", "CONFIDENTIAL"],
        )
        self._model_dependencies["MODEL-101-LEGACY"] = {
            "agents": ["AGENT-LEGACY-09"],
            "applications": ["legacy-billing-app"],
        }
        self._model_dependencies["MODEL-781"] = {
            "agents": ["AGENT-41", "AGENT-DEV-BOT"],
            "applications": ["garuda-copilot", "log-analyzer"],
        }

    def register_record(self, record: AIGovernanceRecord):
        self._governance[record.asset_id] = record

    def get_record(self, asset_id: str) -> Optional[AIGovernanceRecord]:
        return self._governance.get(asset_id)

    def evaluate_model_deprecation(
        self,
        model_id: str,
        current_status: ModelLifecycleStatus,
        replacement_model: Optional[str] = "MODEL-781",
    ) -> ModelDeprecationReport:
        deps = self._model_dependencies.get(model_id, {"agents": [], "applications": []})
        is_bad = current_status in (ModelLifecycleStatus.DEPRECATED, ModelLifecycleStatus.BLOCKED, ModelLifecycleStatus.RETIRED)

        return ModelDeprecationReport(
            model_id=model_id,
            status=current_status,
            is_deprecated_or_blocked=is_bad,
            dependent_agents=deps.get("agents", []),
            dependent_applications=deps.get("applications", []),
            recommended_replacement_model=replacement_model if is_bad else None,
            migration_deadline=time.time() + (30 * 86400) if is_bad else None,
        )
