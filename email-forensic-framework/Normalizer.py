"""
Feature normalization / scaling pipeline (Phase 5, Section 41-42, 50-51).

Binary and one-hot features are never scaled (Section 42). Only continuous
numeric features go through a scaler, and the scaler's fitted parameters are
learned once on a training set and then reused verbatim at inference time
(Section 50-51) - never refit per-PCAP.
"""

import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from .registry import DEFAULT_REGISTRY, FeatureDType, FeatureRegistry
except (ImportError, ValueError):
    from registry import DEFAULT_REGISTRY, FeatureDType, FeatureRegistry


@dataclass
class ScalerParams:
    method: str  # "standard" or "robust"
    center: Dict[str, float] = field(default_factory=dict)   # mean or median
    scale: Dict[str, float] = field(default_factory=dict)    # std or IQR

    def to_dict(self) -> dict:
        return {"method": self.method, "center": self.center, "scale": self.scale}

    @classmethod
    def from_dict(cls, d: dict) -> "ScalerParams":
        return cls(method=d["method"], center=d["center"], scale=d["scale"])

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "ScalerParams":
        with open(path) as f:
            return cls.from_dict(json.load(f))


def _numeric_feature_names(registry: FeatureRegistry) -> List[str]:
    return [d.name for d in registry.all() if d.dtype == FeatureDType.NUMERIC]


def _median(values: List[float]) -> float:
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 0:
        return (s[mid - 1] + s[mid]) / 2.0
    return s[mid]


def _iqr(values: List[float]) -> float:
    try:
        from .temporal import _percentile
    except (ImportError, ValueError):
        from temporal import _percentile
    q1 = _percentile(values, 25)
    q3 = _percentile(values, 75)
    return q3 - q1


def _to_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float, str)):
            res = float(value)
            return res if not math.isnan(res) else None
        return None
    except (TypeError, ValueError):
        return None


def fit_scaler(
    rows: List[Dict[str, Any]],
    method: str = "robust",
    registry: FeatureRegistry = DEFAULT_REGISTRY,
) -> ScalerParams:
    """
    Fits scaling parameters on a *training* set of already-encoded feature
    rows. `method`="robust" uses median/IQR (recommended for heavy-tailed
    network features per Section 41); "standard" uses mean/std.
    """
    numeric_names = _numeric_feature_names(registry)
    center: Dict[str, float] = {}
    scale: Dict[str, float] = {}

    for name in numeric_names:
        values: List[float] = []
        for r in rows:
            if name in r:
                val = _to_float(r[name])
                if val is not None:
                    values.append(val)

        if not values:
            center[name] = 0.0
            scale[name] = 1.0
            continue
        if method == "standard":
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            center[name] = mean
            scale[name] = math.sqrt(variance) or 1.0
        else:  # robust
            med = _median(values)
            iqr = _iqr(values)
            center[name] = med
            scale[name] = iqr if iqr > 0 else 1.0

    return ScalerParams(method=method, center=center, scale=scale)


def apply_scaler(
    row: Dict[str, Any],
    scaler: ScalerParams,
    registry: FeatureRegistry = DEFAULT_REGISTRY,
) -> Dict[str, Any]:
    """
    Applies frozen scaler parameters to one encoded feature row (Section 50:
    the inference pipeline reuses exactly the training-time scaler, never
    refitting). Binary/categorical features pass through unchanged.
    """
    numeric_names = set(_numeric_feature_names(registry))
    out = dict(row)
    for name in numeric_names:
        if name not in row:
            continue
        val = _to_float(row[name])
        if val is None:
            continue
        c = scaler.center.get(name, 0.0)
        s = scaler.scale.get(name, 1.0) or 1.0
        out[name] = (val - c) / s
    return out
