"""
Phase 25 — Detection Engineering Package
Versioned detection rules, historical replay, regression testing, and threat hunt promotion.
"""

from .rules.models import DetectionRuleDefinition, DetectionRuleRepository
from .replay.engine import HistoricalReplayEngine
from .testing.regression import DetectionRegressionTester
from .deployment.promoter import ThreatHuntPromoter

__all__ = [
    "DetectionRuleDefinition",
    "DetectionRuleRepository",
    "HistoricalReplayEngine",
    "DetectionRegressionTester",
    "ThreatHuntPromoter",
]
