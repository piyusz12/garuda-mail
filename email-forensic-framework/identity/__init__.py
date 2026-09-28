"""
Identity Intelligence & Fabric Root Package.
Provides ingestion, normalization, graph modeling, posture, risk, and lifecycle.
"""
from .ingestion import (
    UserIdentity,
    UserIdentityRepository,
    IdentityStatus,
    DeviceIdentity,
    DeviceIdentityRepository,
    DeviceType,
    DeviceComplianceStatus,
    ServiceIdentity,
    ServiceIdentityRepository,
    ResourceClassification,
    WorkloadIdentity,
    WorkloadIdentityRepository,
)
from .normalization import (
    IdentityResolver,
    CertificateIdentityBinding,
    SessionIdentityBinding,
)
from .graph import (
    IdentityNode,
    IdentityNodeType,
    IdentityEdge,
    IdentityEdgeType,
    TemporalIdentityGraph,
)
from .posture import (
    DevicePostureState,
    DevicePostureLevel,
    DevicePostureEvaluator,
    IdentityPostureState,
    IdentityPostureLevel,
    IdentityPostureEvaluator,
    ServicePostureState,
    ServicePostureEvaluator,
)
from .risk import (
    IdentityBehaviorBaseline,
    BehavioralAnalyticsEngine,
    SessionRiskScore,
    SessionRiskLevel,
    SessionRiskEngine,
    IdentityRiskAssessment,
    IdentityRiskLevel,
    IdentityRiskEngine,
)
from .lifecycle import (
    IdentityLifecycleManager,
    IdentityLifecycleError,
    AccessGrant,
    AccessState,
    AccessLifecycleManager,
    DeviceLifecycleManager,
)

__all__ = [
    # Ingestion
    "UserIdentity", "UserIdentityRepository", "IdentityStatus",
    "DeviceIdentity", "DeviceIdentityRepository", "DeviceType", "DeviceComplianceStatus",
    "ServiceIdentity", "ServiceIdentityRepository", "ResourceClassification",
    "WorkloadIdentity", "WorkloadIdentityRepository",

    # Normalization
    "IdentityResolver", "CertificateIdentityBinding", "SessionIdentityBinding",

    # Graph
    "IdentityNode", "IdentityNodeType", "IdentityEdge", "IdentityEdgeType", "TemporalIdentityGraph",

    # Posture
    "DevicePostureState", "DevicePostureLevel", "DevicePostureEvaluator",
    "IdentityPostureState", "IdentityPostureLevel", "IdentityPostureEvaluator",
    "ServicePostureState", "ServicePostureEvaluator",

    # Risk
    "IdentityBehaviorBaseline", "BehavioralAnalyticsEngine",
    "SessionRiskScore", "SessionRiskLevel", "SessionRiskEngine",
    "IdentityRiskAssessment", "IdentityRiskLevel", "IdentityRiskEngine",

    # Lifecycle
    "IdentityLifecycleManager", "IdentityLifecycleError",
    "AccessGrant", "AccessState", "AccessLifecycleManager", "DeviceLifecycleManager",
]
