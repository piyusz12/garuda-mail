"""
Baseline distribution statistics & contextual rarity features
(Phase 5, Section 52-57).

Section 57 is the critical rule this module exists to enforce: baseline
statistics (mean/std/percentiles) must be frozen from historical data
*before* scoring, and never recomputed from the session being scored.
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _median(values: List[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 0:
        return (s[mid - 1] + s[mid]) / 2.0
    return s[mid]


def _pstdev(values: List[float]) -> float:
    if len(values) <= 1:
        return 0.0
    m = _mean(values)
    variance = sum((x - m) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


@dataclass
class FeatureBaselineStats:
    mean: float
    std: float
    median: float
    min: float
    max: float
    p1: float
    p5: float
    p25: float
    p50: float
    p75: float
    p95: float
    p99: float


def compute_baseline_stats(values: List[float]) -> Optional[FeatureBaselineStats]:
    """Section 52: compute the full baseline distribution summary for one numeric feature."""
    if not values:
        return None
    try:
        from .temporal import _percentile
    except (ImportError, ValueError):
        from temporal import _percentile

    return FeatureBaselineStats(
        mean=_mean(values),
        std=_pstdev(values),
        median=_median(values),
        min=min(values),
        max=max(values),
        p1=_percentile(values, 1),
        p5=_percentile(values, 5),
        p25=_percentile(values, 25),
        p50=_percentile(values, 50),
        p75=_percentile(values, 75),
        p95=_percentile(values, 95),
        p99=_percentile(values, 99),
    )


@dataclass
class ProtocolBaseline:
    """Section 54-55: baseline stats kept per-protocol to avoid one protocol
    (e.g. SMTP, if it dominates the traffic mix) defining "normal" for all."""

    stats_by_protocol: Dict[str, Dict[str, FeatureBaselineStats]] = field(default_factory=dict)

    def get(self, protocol: str, feature_name: str) -> Optional[FeatureBaselineStats]:
        return self.stats_by_protocol.get(protocol, {}).get(feature_name)


def zscore(value: Optional[float], baseline: Optional[FeatureBaselineStats]) -> Optional[float]:
    """Section 56: (value - baseline.mean) / baseline.std, guarding std==0."""
    if value is None or baseline is None or baseline.std == 0:
        return None
    return (value - baseline.mean) / baseline.std


def percentile_rank(value: Optional[float], baseline: Optional[FeatureBaselineStats], sample: List[float]) -> Optional[float]:
    """
    Percentile of `value` within the frozen baseline `sample` (Section 56,
    e.g. ja4_frequency_percentile, cipher_frequency_percentile). `sample`
    should be the raw baseline values the FeatureBaselineStats was built from.
    """
    if value is None or not sample:
        return None
    below_or_equal = sum(1 for v in sample if v <= value)
    return below_or_equal / len(sample)


def extract_contextual_rarity_features(
    session_features: Dict[str, Any],
    protocol: str,
    baseline: Optional[ProtocolBaseline],
    feature_names: List[str],
) -> Dict[str, Any]:
    """
    Given already-extracted raw features for one session, compute z-scores
    against a frozen per-protocol baseline for the requested numeric
    features. Returns keys like "<feature_name>.zscore".
    """
    out: Dict[str, Any] = {}
    if baseline is None:
        return {f"{name}.zscore": None for name in feature_names}
    for name in feature_names:
        b = baseline.get(protocol, name)
        raw_val = session_features.get(name)
        val_float: Optional[float] = None
        if isinstance(raw_val, (int, float)):
            val_float = float(raw_val)
        out[f"{name}.zscore"] = zscore(val_float, b)
    return out
