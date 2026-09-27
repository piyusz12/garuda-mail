"""Validation package initialization."""
from .datasets import LabeledEvent, ValidationDatasetRepository
from .metrics import DetectionPerformanceMetrics
from .simulation import DetectionSimulator, SimulationResult
from .backtest import DetectionBacktester, BacktestReport, BacktestWindowResult
from .regression import DetectionRegressionTester, RegressionComparison

__all__ = [
    "LabeledEvent", "ValidationDatasetRepository",
    "DetectionPerformanceMetrics",
    "DetectionSimulator", "SimulationResult",
    "DetectionBacktester", "BacktestReport", "BacktestWindowResult",
    "DetectionRegressionTester", "RegressionComparison"
]
