"""
Human-in-the-Loop Data Classification Review Workflow.
Component 29.14: Workflow for ambiguous or low-confidence auto-classifications.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid

from data_security.inventory.normalization import ClassificationLevel


class ReviewStatus(str, Enum):
    AUTO_CLASSIFIED = "AUTO_CLASSIFIED"
    PENDING_HUMAN_REVIEW = "PENDING_HUMAN_REVIEW"
    APPROVED = "APPROVED"
    OVERRIDDEN = "OVERRIDDEN"


@dataclass
class ClassificationReviewRecord:
    review_id: str
    data_asset_id: str
    proposed_classification: ClassificationLevel
    final_classification: Optional[ClassificationLevel] = None
    status: ReviewStatus = ReviewStatus.PENDING_HUMAN_REVIEW
    confidence: float = 0.70
    signals_summary: List[str] = field(default_factory=list)
    reviewer_identity: Optional[str] = None
    review_notes: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    reviewed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "review_id": self.review_id,
            "data_asset_id": self.data_asset_id,
            "proposed_classification": self.proposed_classification.value,
            "final_classification": self.final_classification.value if self.final_classification else None,
            "status": self.status.value,
            "confidence": self.confidence,
            "signals_summary": self.signals_summary,
            "reviewer_identity": self.reviewer_identity,
            "review_notes": self.review_notes,
            "created_at": self.created_at,
            "reviewed_at": self.reviewed_at,
        }


class ClassificationReviewManager:
    """Manages pending and completed human review workflows for data classification."""

    def __init__(self):
        self._reviews: Dict[str, ClassificationReviewRecord] = {}

    def create_review_request(
        self,
        data_asset_id: str,
        proposed_level: ClassificationLevel,
        confidence: float,
        signals: List[str],
    ) -> ClassificationReviewRecord:
        record = ClassificationReviewRecord(
            review_id=f"REV-{uuid.uuid4().hex[:8].upper()}",
            data_asset_id=data_asset_id,
            proposed_classification=proposed_level,
            confidence=confidence,
            signals_summary=signals,
            status=ReviewStatus.PENDING_HUMAN_REVIEW,
        )
        self._reviews[record.review_id] = record
        return record

    def submit_review(
        self,
        review_id: str,
        reviewer: str,
        approved_level: ClassificationLevel,
        notes: str = "Steward approved classification",
    ) -> Optional[ClassificationReviewRecord]:
        rec = self._reviews.get(review_id)
        if not rec:
            return None
        rec.reviewer_identity = reviewer
        rec.final_classification = approved_level
        rec.status = ReviewStatus.APPROVED if approved_level == rec.proposed_classification else ReviewStatus.OVERRIDDEN
        rec.review_notes = notes
        rec.reviewed_at = time.time()
        return rec

    def list_pending_reviews(self) -> List[ClassificationReviewRecord]:
        return [r for r in self._reviews.values() if r.status == ReviewStatus.PENDING_HUMAN_REVIEW]

    def get_review(self, review_id: str) -> Optional[ClassificationReviewRecord]:
        return self._reviews.get(review_id)
