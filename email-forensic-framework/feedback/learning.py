"""
Phase 23 - Feedback Learning, False Positive Analysis, and Autonomous Recurrence Monitoring.
Transforms analyst feedback into detection tuning and tracks post-remediation recurrence.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import collections

from .analyst_labels import AnalystFeedbackCollector, AnalystFeedbackRecord

@dataclass
class FalsePositiveCluster:
    detection_id: str
    total_false_positives: int
    by_asset: Dict[str, float]  # Percentage breakdown, e.g. {"MTA-07": 82.0}
    by_ja4: Dict[str, float]
    recommended_tuning: str

@dataclass
class RecurrenceWatcher:
    watcher_id: str
    finding_id: str
    asset_id: str
    pattern_signature: str
    remediation_date: datetime
    watch_until: datetime
    is_active: bool = True
    recurrence_count: int = 0


class DetectionLearningEngine:
    """Analyzes FP distributions, recommends rule tuning, and manages post-remediation watchers."""

    def __init__(self, feedback_collector: Optional[AnalystFeedbackCollector] = None):
        self.feedback_collector = feedback_collector or AnalystFeedbackCollector()
        self.watchers: Dict[str, RecurrenceWatcher] = {}

    def analyze_false_positives(self, detection_id: str) -> Optional[FalsePositiveCluster]:
        records = self.feedback_collector.get_feedback_for_detection(detection_id)
        fps = [r for r in records if r.verdict == "FALSE_POSITIVE"]

        if not fps:
            return None

        asset_counts = collections.Counter([r.context.get("asset", "UNKNOWN") for r in fps])
        ja4_counts = collections.Counter([r.context.get("ja4", "UNKNOWN") for r in fps])
        total = len(fps)

        by_asset = {k: round((v / total) * 100, 1) for k, v in asset_counts.items()}
        by_ja4 = {k: round((v / total) * 100, 1) for k, v in ja4_counts.items()}

        # Suggest tuning if single asset dominates (> 50%)
        top_asset, top_asset_pct = asset_counts.most_common(1)[0]
        tuning_rec = "Rule performs evenly across fleet."
        if (top_asset_pct / total) >= 0.50:
            tuning_rec = f"High skew: Asset '{top_asset}' accounts for {by_asset[top_asset]}% of FPs. Recommend creating an asset-specific baseline exclusion."

        return FalsePositiveCluster(
            detection_id=detection_id,
            total_false_positives=total,
            by_asset=by_asset,
            by_ja4=by_ja4,
            recommended_tuning=tuning_rec
        )

    def create_remediation_watcher(self, finding_id: str, asset_id: str, pattern: str, grace_days: int = 90) -> RecurrenceWatcher:
        import uuid
        now = datetime.now(timezone.utc)
        w_id = f"WATCH-{uuid.uuid4().hex[:6].upper()}"
        watcher = RecurrenceWatcher(
            watcher_id=w_id,
            finding_id=finding_id,
            asset_id=asset_id,
            pattern_signature=pattern,
            remediation_date=now,
            watch_until=now + timedelta(days=grace_days),
            is_active=True
        )
        self.watchers[w_id] = watcher
        return watcher

    def check_telemetry_for_recurrence(self, asset_id: str, observed_pattern: str) -> List[RecurrenceWatcher]:
        """Checks if newly observed telemetry violates a post-remediation watcher."""
        triggered = []
        now = datetime.now(timezone.utc)
        for w in self.watchers.values():
            if w.is_active and w.asset_id == asset_id and w.watch_until >= now:
                if w.pattern_signature.lower() in observed_pattern.lower() or observed_pattern.lower() in w.pattern_signature.lower():
                    w.recurrence_count += 1
                    triggered.append(w)
        return triggered
