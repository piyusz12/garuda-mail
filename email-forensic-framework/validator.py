"""
Feature validation (Phase 5, Section 45-46).

Returns structured errors rather than raising, so a single malformed
session doesn't crash a whole batch extraction run (Section 46).
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List

try:
    from .registry import DEFAULT_REGISTRY, FeatureDType, FeatureRegistry
except (ImportError, ValueError):
    from registry import DEFAULT_REGISTRY, FeatureDType, FeatureRegistry


@dataclass
class ValidationResult:
    passed: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def validate_features(
    features: Dict[str, Any],
    registry: FeatureRegistry = DEFAULT_REGISTRY,
) -> ValidationResult:
    errors: List[str] = []
    warnings: List[str] = []

    for defn in registry.all():
        if defn.name not in features:
            warnings.append(f"missing feature key: {defn.name}")
            continue

        value = features[defn.name]

        if value is None:
            # Allowed pre-encoding (NaN-policy features arrive as None here);
            # the encoder step is what fills these. Not an error at this stage.
            continue

        if defn.dtype == FeatureDType.BINARY:
            if value not in (0, 1, 0.0, 1.0):
                errors.append(f"{defn.name}: binary feature has non-binary value {value!r}")
            continue

        if defn.dtype == FeatureDType.NUMERIC:
            if not isinstance(value, (int, float, str)):
                errors.append(f"{defn.name}: expected numeric, got {value!r}")
                continue
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                errors.append(f"{defn.name}: expected numeric, got {value!r}")
                continue
            if math.isnan(numeric):
                continue  # NaN is a valid, explicit missing marker
            if math.isinf(numeric):
                errors.append(f"{defn.name}: value is infinite")
                continue
            if defn.valid_range is not None:
                lo, hi = defn.valid_range
                if lo is not None and numeric < lo:
                    errors.append(f"{defn.name}: {numeric} below minimum {lo}")
                if hi is not None and numeric > hi:
                    errors.append(f"{defn.name}: {numeric} above maximum {hi}")

    return ValidationResult(passed=(len(errors) == 0), errors=errors, warnings=warnings)
