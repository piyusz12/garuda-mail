"""
Missing-data strategy & encoding (Phase 5, Section 34-35, 41-43).

Two things happen here, deliberately kept separate from raw extraction:

1. Missing-value filling per the registry's declared MissingPolicy, plus
   generation of `<feature>_available` masks (Section 35) so the model can
   learn that missing data has a specific, structured cause rather than
   conflating "not observed" with "not present".
2. Log-transform companions for heavy-tailed count/byte/duration features
   (Section 43), added alongside - not instead of - the raw values.
"""

import math
from typing import Any, Dict, List, Optional

try:
    from .registry import DEFAULT_REGISTRY, FeatureRegistry, MissingPolicy
except (ImportError, ValueError):
    from registry import DEFAULT_REGISTRY, FeatureRegistry, MissingPolicy

# Features that are conventionally heavy-tailed and benefit from a log1p companion.
LOG_TRANSFORM_CANDIDATES = [
    "flow.total_bytes", "flow.client_bytes", "flow.server_bytes",
    "flow.packet_count", "timing.session_duration",
    "ja4.session_frequency",
]


def apply_missing_policy(
    raw_features: Dict[str, Any],
    registry: FeatureRegistry = DEFAULT_REGISTRY,
) -> Dict[str, Any]:
    """
    Fills missing (None) values per each feature's declared MissingPolicy,
    and emits a `<name>_available` companion for every feature the registry
    marks with has_availability_mask=True (Section 35).
    """
    filled: Dict[str, Any] = {}

    for defn in registry.all():
        value = raw_features.get(defn.name)
        is_missing = value is None

        if defn.has_availability_mask:
            filled[f"{defn.name}_available"] = int(not is_missing)

        if not is_missing:
            filled[defn.name] = value
            continue

        if defn.missing_policy == MissingPolicy.ZERO:
            filled[defn.name] = 0
        elif defn.missing_policy == MissingPolicy.FALSE:
            filled[defn.name] = 0
        elif defn.missing_policy == MissingPolicy.NAN:
            filled[defn.name] = float("nan")
        elif defn.missing_policy == MissingPolicy.UNKNOWN_CATEGORY:
            filled[defn.name] = "UNKNOWN"
        else:
            filled[defn.name] = None

    # Carry through any keys not in the registry (e.g. contextual .zscore
    # features computed after the fact) unchanged.
    for key, value in raw_features.items():
        if key not in filled:
            filled[key] = value if value is not None else float("nan")

    return filled


def add_log_transforms(features: Dict[str, Any], candidates: Optional[List[str]] = None) -> Dict[str, Any]:
    """Section 43: x' = log(1 + x), stored alongside the raw value, never replacing it."""
    candidates = candidates if candidates is not None else LOG_TRANSFORM_CANDIDATES
    out = dict(features)
    for name in candidates:
        value = features.get(name)
        if value is None:
            continue
        try:
            if isinstance(value, (int, float, str)):
                numeric = float(value)
            else:
                continue
        except (TypeError, ValueError):
            continue
        if math.isnan(numeric):
            continue
        out[f"{name}_log"] = math.log1p(max(numeric, 0.0))
    return out
