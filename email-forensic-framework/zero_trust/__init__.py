"""
PHASE 27 — Enterprise Zero Trust, Identity Intelligence & Adaptive Access Control.
Zero Trust Control Plane Package Initialization.
"""
from .policy import (
    ZeroTrustPolicy,
    PolicyEffect,
    PolicyCondition,
    PolicyDSLParser,
    PolicyCompiler,
    CompiledPolicy,
    PolicyValidator,
    PolicyValidationError,
    PolicyConflictDetector,
    PolicyConflict,
)
from .decision import (
    AccessRequestContext,
    TrustContext,
    PolicyDecisionPoint,
    AccessDecisionRecord,
    PolicyDecisionExplainer,
)
from .enforcement import (
    PolicyEnforcementPoint,
    EnforcementAction,
    EnforcementResult,
    ServiceToServiceGateway,
)
from .sessions import (
    ActiveSession,
    SessionStatus,
    SessionMonitor,
    ReevaluationEvent,
    ReevaluationResult,
    ContinuousAccessEvaluator,
    SessionRevocationManager,
)
from .privilege import (
    JITRequest,
    JITStatus,
    JITAccessManager,
    JEPAScoper,
    BreakGlassSession,
    BreakGlassStatus,
    EmergencyAccessController,
)
from .simulation import (
    AccessSimulationResult,
    AccessSimulator,
    PolicyBlastRadiusAssessment,
    PolicyBlastRadiusAnalyzer,
    PolicyRegressionReport,
    PolicyRegressionTester,
)
from .governance import (
    ReviewDecision,
    AccessReviewItem,
    AccessCertificationCampaign,
    PolicyException,
    PolicyExceptionManager,
    SignedPolicyBundle,
    PolicyBundleDistributor,
)
from .copilot import IdentityCopilot

__all__ = [
    # Policy
    "ZeroTrustPolicy", "PolicyEffect", "PolicyCondition", "PolicyDSLParser",
    "PolicyCompiler", "CompiledPolicy", "PolicyValidator", "PolicyValidationError",
    "PolicyConflictDetector", "PolicyConflict",

    # Decision
    "AccessRequestContext", "TrustContext", "PolicyDecisionPoint",
    "AccessDecisionRecord", "PolicyDecisionExplainer",

    # Enforcement
    "PolicyEnforcementPoint", "EnforcementAction", "EnforcementResult", "ServiceToServiceGateway",

    # Sessions
    "ActiveSession", "SessionStatus", "SessionMonitor",
    "ReevaluationEvent", "ReevaluationResult", "ContinuousAccessEvaluator", "SessionRevocationManager",

    # Privilege
    "JITRequest", "JITStatus", "JITAccessManager", "JEPAScoper",
    "BreakGlassSession", "BreakGlassStatus", "EmergencyAccessController",

    # Simulation
    "AccessSimulationResult", "AccessSimulator",
    "PolicyBlastRadiusAssessment", "PolicyBlastRadiusAnalyzer",
    "PolicyRegressionReport", "PolicyRegressionTester",

    # Governance
    "ReviewDecision", "AccessReviewItem", "AccessCertificationCampaign",
    "PolicyException", "PolicyExceptionManager", "SignedPolicyBundle", "PolicyBundleDistributor",

    # Copilot
    "IdentityCopilot",
]
