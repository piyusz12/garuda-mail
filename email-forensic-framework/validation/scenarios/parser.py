"""
Scenario Parser & YAML/JSON Importer.
Validates syntax, structure, preconditions, and safety boundaries of scenario definitions.
"""
from typing import Dict, List, Optional, Any
import json
import yaml
from .builder import ValidationScenario, ScenarioStep, ScenarioBlastRadius
from .oracle import ScenarioOracle


class ScenarioParseError(Exception):
    pass


class ScenarioParser:
    """Parses and validates declarative scenario specifications."""

    @staticmethod
    def parse_dict(data: Dict[str, Any]) -> ValidationScenario:
        # Check required fields
        required = ["scenario_id", "name", "target_assets", "oracle"]
        for req in required:
            if req not in data:
                raise ScenarioParseError(f"Missing required field in scenario definition: {req}")

        steps = []
        for idx, s in enumerate(data.get("steps", [])):
            steps.append(ScenarioStep(
                step_id=s.get("step_id", f"step-{idx + 1}"),
                sequence_order=s.get("sequence_order", idx + 1),
                technique_id=s.get("technique_id", "TECH-042"),
                action_type=s.get("action_type", "emit_telemetry"),
                parameters=s.get("parameters", {}),
                pause_seconds_after=float(s.get("pause_seconds_after", 0.2)),
            ))

        oracle_data = data.get("oracle", {})
        oracle = ScenarioOracle(
            expected_telemetry=oracle_data.get("expected_telemetry", []),
            expected_detections=oracle_data.get("expected_detections", []),
            expected_case_created=bool(oracle_data.get("expected_case_created", True)),
            expected_response_action=oracle_data.get("expected_response_action"),
            expected_approval_required=bool(oracle_data.get("expected_approval_required", False)),
            expected_verification_criteria=oracle_data.get("expected_verification_criteria", {}),
            acceptable_ttd_seconds=float(oracle_data.get("acceptable_ttd_seconds", 30.0)),
            acceptable_ttr_seconds=float(oracle_data.get("acceptable_ttr_seconds", 60.0)),
        )

        blast = ScenarioBlastRadius.LOW
        if data.get("blast_radius") == "MEDIUM":
            blast = ScenarioBlastRadius.MEDIUM
        elif data.get("blast_radius") == "HIGH":
            blast = ScenarioBlastRadius.HIGH

        return ValidationScenario(
            scenario_id=str(data["scenario_id"]),
            name=str(data["name"]),
            version=str(data.get("version", "1.0.0")),
            description=str(data.get("description", "")),
            environment_type=str(data.get("environment_type", "cyber_range")),
            target_assets=list(data["target_assets"]),
            adversary_profile_id=data.get("adversary_profile_id"),
            preconditions=list(data.get("preconditions", ["target_exists", "telemetry_enabled"])),
            steps=steps,
            oracle=oracle,
            cleanup_actions=list(data.get("cleanup_actions", ["restore_original_state"])),
            blast_radius=blast,
            tags=list(data.get("tags", [])),
            author_id=str(data.get("author_id", "security-engineer-01")),
        )

    @classmethod
    def parse_yaml(cls, yaml_content: str) -> ValidationScenario:
        try:
            data = yaml.safe_load(yaml_content)
            return cls.parse_dict(data)
        except Exception as e:
            raise ScenarioParseError(f"Failed to parse scenario YAML: {str(e)}")

    @classmethod
    def parse_json(cls, json_content: str) -> ValidationScenario:
        try:
            data = json.loads(json_content)
            return cls.parse_dict(data)
        except Exception as e:
            raise ScenarioParseError(f"Failed to parse scenario JSON: {str(e)}")
