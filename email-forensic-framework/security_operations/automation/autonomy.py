"""
Phase 25 — Safe Autonomy Levels
Defines the hierarchical automation gates governing operational security actions.
"""

from enum import IntEnum


class AutonomyLevel(IntEnum):
    LEVEL_0_OBSERVE = 0      # Telemetry collection, logging, read-only inspection
    LEVEL_1_RECOMMEND = 1    # Generate explainable recommendations for human analyst
    LEVEL_2_PREPARE = 2      # Stage response plans, pre-calculate blast radius & simulation
    LEVEL_3_LOW_IMPACT = 3   # Autonomous execution for R0-R2 non-disruptive/reversible actions
    LEVEL_4_FULL_SOAR = 4    # Multi-stage autonomous response including canary rollouts
