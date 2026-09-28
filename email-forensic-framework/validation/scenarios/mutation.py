"""
Scenario Mutation Engine & Scenario Family Generator.
Generates controlled variations to test detector resilience and AI model robustness.
"""
from typing import Dict, List, Optional, Any
import copy
import random
from .builder import ValidationScenario, ScenarioStep


class ScenarioMutationEngine:
    """Mutates base scenarios to evaluate detector robustness under perturbation."""

    @classmethod
    def generate_family(cls, base_scenario: ValidationScenario, count: int = 3) -> List[ValidationScenario]:
        """Creates a family of mutant scenarios with subtle parameter variations."""
        family = []

        tls_variants = ["TLS 1.0", "TLS 1.1", "SSLv3"]
        ja4_variants = [
            "t10d0100h0_legacy_variant1",
            "t11d0200h1_legacy_variant2",
            "t10d9999h0_anomalous_burst",
        ]
        timing_jitters = [0.1, 0.4, 0.8]

        for i in range(count):
            mutated = copy.deepcopy(base_scenario)
            mutated.scenario_id = f"{base_scenario.scenario_id}-MUT-{i+1}"
            mutated.name = f"{base_scenario.name} (Variant {i+1})"
            mutated.tags.append("mutated")

            for step in mutated.steps:
                # Apply timing jitter
                step.pause_seconds_after = timing_jitters[i % len(timing_jitters)]

                # Perturb parameters if relevant
                if "tls_version" in step.parameters:
                    step.parameters["tls_version"] = tls_variants[i % len(tls_variants)]
                if "ja4" in step.parameters:
                    step.parameters["ja4"] = ja4_variants[i % len(ja4_variants)]
                if "cert_id" in step.parameters:
                    step.parameters["cert_id"] = f"{step.parameters['cert_id']}-VAR{i+1}"

            family.append(mutated)

        return family
