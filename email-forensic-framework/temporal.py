"""
Temporal Feature Extraction and Statistical Utilities (Phase 5).
Provides percentile computation and time-series extraction for session events.
"""

import math
from typing import Any, Dict, List, Optional


def _percentile(values: List[float], p: float) -> float:
    """
    Computes the p-th percentile (0 <= p <= 100) of a list of floats.
    Uses linear interpolation between data points.
    """
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    if n == 1:
        return float(s[0])
    if p <= 0:
        return float(s[0])
    if p >= 100:
        return float(s[-1])

    k = (n - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(s[int(k)])
    d0 = s[int(f)] * (c - k)
    d1 = s[int(c)] * (k - f)
    return float(d0 + d1)


def extract_temporal_features(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extracts temporal features from a sequence of session packets or protocol events:
    - duration
    - packet count
    - inter-arrival times (mean, std, min, max, median, iqr)
    """
    if not events:
        return {
            "timing.session_duration": 0.0,
            "timing.inter_arrival_mean": 0.0,
            "timing.inter_arrival_std": 0.0,
            "timing.inter_arrival_median": 0.0,
        }

    timestamps: List[float] = []
    for e in events:
        ts = e.get("timestamp")
        if isinstance(ts, (int, float)):
            timestamps.append(float(ts))

    if len(timestamps) < 2:
        return {
            "timing.session_duration": 0.0,
            "timing.inter_arrival_mean": 0.0,
            "timing.inter_arrival_std": 0.0,
            "timing.inter_arrival_median": 0.0,
        }

    timestamps.sort()
    duration = max(0.0, timestamps[-1] - timestamps[0])
    deltas = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

    mean_delta = sum(deltas) / len(deltas)
    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
    std_delta = math.sqrt(variance)

    return {
        "timing.session_duration": duration,
        "timing.inter_arrival_mean": mean_delta,
        "timing.inter_arrival_std": std_delta,
        "timing.inter_arrival_median": _percentile(deltas, 50),
    }
