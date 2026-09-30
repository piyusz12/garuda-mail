"""
Feature Registry (Phase 5, Section 34-38).
Declares feature definitions, types, missing data policies, and validation boundaries.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class FeatureDType(str, Enum):
    NUMERIC = "numeric"
    BINARY = "binary"
    CATEGORICAL = "categorical"
    STRING = "string"


class MissingPolicy(str, Enum):
    ZERO = "zero"
    FALSE = "false"
    NAN = "nan"
    UNKNOWN_CATEGORY = "unknown_category"
    NONE = "none"


@dataclass
class FeatureDefinition:
    name: str
    dtype: FeatureDType
    missing_policy: MissingPolicy = MissingPolicy.ZERO
    has_availability_mask: bool = False
    valid_range: Optional[Tuple[Optional[float], Optional[float]]] = None
    description: Optional[str] = None


class FeatureRegistry:
    def __init__(self):
        self._definitions: Dict[str, FeatureDefinition] = {}

    def register(self, defn: FeatureDefinition) -> None:
        self._definitions[defn.name] = defn

    def get(self, name: str) -> Optional[FeatureDefinition]:
        return self._definitions.get(name)

    def all(self) -> List[FeatureDefinition]:
        return list(self._definitions.values())

    def numeric_features(self) -> List[str]:
        return [d.name for d in self.all() if d.dtype == FeatureDType.NUMERIC]

    def binary_features(self) -> List[str]:
        return [d.name for d in self.all() if d.dtype == FeatureDType.BINARY]


def create_default_registry() -> FeatureRegistry:
    registry = FeatureRegistry()

    # Flow & volume features
    flow_features = [
        FeatureDefinition("flow.total_bytes", FeatureDType.NUMERIC, MissingPolicy.ZERO, True, (0.0, None)),
        FeatureDefinition("flow.client_bytes", FeatureDType.NUMERIC, MissingPolicy.ZERO, True, (0.0, None)),
        FeatureDefinition("flow.server_bytes", FeatureDType.NUMERIC, MissingPolicy.ZERO, True, (0.0, None)),
        FeatureDefinition("flow.packet_count", FeatureDType.NUMERIC, MissingPolicy.ZERO, True, (0.0, None)),
        FeatureDefinition("flow.client_server_ratio", FeatureDType.NUMERIC, MissingPolicy.NAN, False, (0.0, None)),
    ]

    # Timing features
    timing_features = [
        FeatureDefinition("timing.session_duration", FeatureDType.NUMERIC, MissingPolicy.ZERO, True, (0.0, None)),
        FeatureDefinition("timing.inter_arrival_mean", FeatureDType.NUMERIC, MissingPolicy.ZERO, False, (0.0, None)),
        FeatureDefinition("timing.inter_arrival_std", FeatureDType.NUMERIC, MissingPolicy.ZERO, False, (0.0, None)),
        FeatureDefinition("timing.inter_arrival_median", FeatureDType.NUMERIC, MissingPolicy.ZERO, False, (0.0, None)),
    ]

    # TLS & Cryptographic features
    tls_features = [
        FeatureDefinition("tls.version_numeric", FeatureDType.NUMERIC, MissingPolicy.ZERO, True, (0.0, 4.0)),
        FeatureDefinition("tls.cipher_suite_id", FeatureDType.NUMERIC, MissingPolicy.ZERO, True, (0.0, 65535.0)),
        FeatureDefinition("tls.sni_present", FeatureDType.BINARY, MissingPolicy.FALSE, False),
        FeatureDefinition("tls.san_count", FeatureDType.NUMERIC, MissingPolicy.ZERO, False, (0.0, None)),
        FeatureDefinition("tls.cert_validity_days", FeatureDType.NUMERIC, MissingPolicy.NAN, True, (0.0, None)),
    ]

    # JA4 features
    ja4_features = [
        FeatureDefinition("ja4.session_frequency", FeatureDType.NUMERIC, MissingPolicy.ZERO, True, (0.0, None)),
        FeatureDefinition("ja4.is_known_client", FeatureDType.BINARY, MissingPolicy.FALSE, False),
    ]

    # Deterministic Security Findings (Section 31)
    security_rules = [
        "tls_deprecated", "weak_cipher", "weak_certificate", "certificate_expired",
        "hostname_mismatch", "no_forward_secrecy", "plaintext_auth", "starttls_failure",
        "mta_sts_present", "mta_sts_enforced", "mta_sts_tls_mismatch",
        "dane_present", "dane_match", "dane_mismatch", "dnssec_validated",
    ]
    security_features = [
        FeatureDefinition(f"security.{k}", FeatureDType.BINARY, MissingPolicy.FALSE, False)
        for k in security_rules
    ]

    for feat in flow_features + timing_features + tls_features + ja4_features + security_features:
        registry.register(feat)

    return registry


DEFAULT_REGISTRY = create_default_registry()
