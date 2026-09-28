"""
Access Reviews & Certification Automation.
Component 65 & 95: Periodic entitlement reviews, stale privilege identification, and certification workflows.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid

from identity.lifecycle.access import AccessGrant, AccessState, AccessLifecycleManager


class ReviewDecision(str, Enum):
    CERTIFIED_KEEP = "CERTIFIED_KEEP"
    MODIFIED = "MODIFIED"
    REVOKED = "REVOKED"


@dataclass
class AccessReviewItem:
    item_id: str
    grant_id: str
    identity_id: str
    resource_id: str
    action: str
    decision: Optional[ReviewDecision] = None
    reviewer_id: Optional[str] = None
    review_notes: Optional[str] = None
    reviewed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "grant_id": self.grant_id,
            "identity_id": self.identity_id,
            "resource_id": self.resource_id,
            "action": self.action,
            "decision": self.decision.value if isinstance(self.decision, ReviewDecision) else self.decision,
            "reviewer_id": self.reviewer_id,
            "reviewed_at": self.reviewed_at,
        }


class AccessCertificationCampaign:
    """Orchestrates periodic access certification rounds."""

    def __init__(self, campaign_name: str, reviewer_id: str):
        self.campaign_id: str = f"CERT-{uuid.uuid4().hex[:6].upper()}"
        self.campaign_name: str = campaign_name
        self.reviewer_id: str = reviewer_id
        self.items: Dict[str, AccessReviewItem] = {}
        self.created_at: float = time.time()
        self.completed_at: Optional[float] = None

    def populate_from_grants(self, grants: List[AccessGrant]) -> None:
        for g in grants:
            item_id = f"REV-{uuid.uuid4().hex[:6].upper()}"
            self.items[item_id] = AccessReviewItem(
                item_id=item_id,
                grant_id=g.grant_id,
                identity_id=g.identity_id,
                resource_id=g.resource_id,
                action=g.action,
            )

    def submit_decision(self, item_id: str, decision: ReviewDecision, notes: str) -> AccessReviewItem:
        item = self.items.get(item_id)
        if not item:
            raise KeyError(f"Review item {item_id} not found.")
        item.decision = decision
        item.reviewer_id = self.reviewer_id
        item.review_notes = notes
        item.reviewed_at = time.time()
        return item

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "reviewer_id": self.reviewer_id,
            "total_items": len(self.items),
            "completed_items": len([i for i in self.items.values() if i.decision is not None]),
            "created_at": self.created_at,
        }
