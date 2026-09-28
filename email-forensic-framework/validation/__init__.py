"""
PHASE 26 — Continuous Adversary Emulation, Purple Team, Cyber Range & Security Validation.
Root package initialization.
"""
# Backward-compatibility imports from earlier phases
from .datasets import LabeledEvent, ValidationDatasetRepository
from .metrics import DetectionPerformanceMetrics
from .simulation import DetectionSimulator, SimulationResult
from .backtest import DetectionBacktester, BacktestReport, BacktestWindowResult
from .regression import DetectionRegressionTester, RegressionComparison

# Phase 26 Architecture Exports
from .adversary import (
    AdversaryProfile,
    AdversaryProfileRepository,
    AdversaryTier,
    ThreatObjective,
    Technique,
    TechniqueLibrary,
    TechniqueCategory,
    TechniqueRisk,
    AdversaryBehavior,
)
from .range import (
    RangeEnvironment,
    RangeAsset,
    IsolationLevel,
    RangeStatus,
    RangeManager,
    IsolationController,
    RangeTeardownController,
)
from .scenarios import (
    ScenarioOracle,
    GroundTruth,
    ValidationScenario,
    ScenarioStep,
    ScenarioBlastRadius,
    ScenarioBuilder,
    ScenarioRepository,
    ScenarioParser,
    ScenarioMutationEngine,
)
from .execution import (
    ScopeValidator,
    SafetyController,
    SafetyCheckResult,
    KillSwitchManager,
    KillSwitchEvent,
    ScenarioRunner,
    ValidationRun,
    ValidationStepRecord,
    ScenarioOutcome,
)
from .purple_team import (
    PurpleTeamComparator,
    ComparisonDelta,
    CoverageMatrix,
    TechniqueCoverageStatus,
    PurpleTeamEngine,
    PurpleTeamExerciseResult,
)
from .evaluation import (
    ValidationScorecard,
    LatencyMetrics,
    VisibilityEvaluator,
    DetectionEvaluator,
    ResponseEvaluator,
    VerificationEvaluator,
)
from .gaps import (
    ValidationGap,
    GapManager,
    GapType,
    GapSeverity,
    GapStatus,
    GapCorrelationEngine,
    CorrelatedRootCause,
    RemediationRetester,
)
from .campaigns import (
    ValidationCampaign,
    CampaignRun,
    CampaignEngine,
    CampaignStatus,
    ValidationScheduler,
    CampaignSchedule,
    CampaignReportGenerator,
    SignedValidationReport,
)
from .replay import (
    HistoricalValidationReplay,
    HistoricalReplayResult,
    ContinuousRegressionEngine,
    RegressionRunResult,
    ChangeImpactAnalyzer,
)
from .governance import (
    GovernanceRole,
    SeparationOfDutiesController,
    SeparationOfDutiesViolation,
    ApprovalWorkflowManager,
    ScenarioApprovalRequest,
    ApprovalStatus,
    GovernancePolicy,
)
from .copilot import (
    ValidationCopilot,
    CopilotDiagnosis,
    CampaignCopilot,
    CopilotReporting,
)

__all__ = [
    # Legacy
    "LabeledEvent", "ValidationDatasetRepository",
    "DetectionPerformanceMetrics",
    "DetectionSimulator", "SimulationResult",
    "DetectionBacktester", "BacktestReport", "BacktestWindowResult",
    "DetectionRegressionTester", "RegressionComparison",

    # Adversary
    "AdversaryProfile", "AdversaryProfileRepository", "AdversaryTier", "ThreatObjective",
    "Technique", "TechniqueLibrary", "TechniqueCategory", "TechniqueRisk", "AdversaryBehavior",

    # Range
    "RangeEnvironment", "RangeAsset", "IsolationLevel", "RangeStatus", "RangeManager",
    "IsolationController", "RangeTeardownController",

    # Scenarios
    "ScenarioOracle", "GroundTruth", "ValidationScenario", "ScenarioStep", "ScenarioBlastRadius",
    "ScenarioBuilder", "ScenarioRepository", "ScenarioParser", "ScenarioMutationEngine",

    # Execution
    "ScopeValidator", "SafetyController", "SafetyCheckResult", "KillSwitchManager",
    "KillSwitchEvent", "ScenarioRunner", "ValidationRun", "ValidationStepRecord", "ScenarioOutcome",

    # Purple Team
    "PurpleTeamComparator", "ComparisonDelta", "CoverageMatrix", "TechniqueCoverageStatus",
    "PurpleTeamEngine", "PurpleTeamExerciseResult",

    # Evaluation
    "ValidationScorecard", "LatencyMetrics", "VisibilityEvaluator", "DetectionEvaluator",
    "ResponseEvaluator", "VerificationEvaluator",

    # Gaps
    "ValidationGap", "GapManager", "GapType", "GapSeverity", "GapStatus",
    "GapCorrelationEngine", "CorrelatedRootCause", "RemediationRetester",

    # Campaigns
    "ValidationCampaign", "CampaignRun", "CampaignEngine", "CampaignStatus",
    "ValidationScheduler", "CampaignSchedule", "CampaignReportGenerator", "SignedValidationReport",

    # Replay
    "HistoricalValidationReplay", "HistoricalReplayResult", "ContinuousRegressionEngine",
    "RegressionRunResult", "ChangeImpactAnalyzer",

    # Governance
    "GovernanceRole", "SeparationOfDutiesController", "SeparationOfDutiesViolation",
    "ApprovalWorkflowManager", "ScenarioApprovalRequest", "ApprovalStatus", "GovernancePolicy",

    # Copilot
    "ValidationCopilot", "CopilotDiagnosis", "CampaignCopilot", "CopilotReporting",
]
