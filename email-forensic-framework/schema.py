"""
Feature Schema Export and Serialization (Phase 5, Section 39, 48).
"""

import json
from typing import Dict, List, Optional

try:
    from .registry import DEFAULT_REGISTRY, FeatureRegistry
except (ImportError, ValueError):
    from registry import DEFAULT_REGISTRY, FeatureRegistry

FEATURE_SCHEMA_VERSION = "1.0.0"


def feature_names(registry: FeatureRegistry = DEFAULT_REGISTRY) -> List[str]:
    """Returns the stable, ordered list of feature names defined in the registry."""
    return [d.name for d in registry.all()]


def get_schema_dict(registry: FeatureRegistry = DEFAULT_REGISTRY) -> dict:
    """Returns a serializable dictionary representation of the feature schema."""
    features = []
    for d in registry.all():
        features.append({
            "name": d.name,
            "dtype": d.dtype.value,
            "missing_policy": d.missing_policy.value,
            "has_availability_mask": d.has_availability_mask,
            "valid_range": list(d.valid_range) if d.valid_range else None,
            "description": d.description,
        })
    return {
        "version": FEATURE_SCHEMA_VERSION,
        "feature_count": len(features),
        "features": features,
    }


def write_schema(path: str, registry: FeatureRegistry = DEFAULT_REGISTRY) -> None:
    """Writes the schema dictionary to the specified JSON path."""
    with open(path, "w") as f:
        json.dump(get_schema_dict(registry), f, indent=2)
