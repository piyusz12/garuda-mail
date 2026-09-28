"""
Validation Scenario Builder.
Constructs safe, auditable, reproducible adversary emulation scenarios.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import uuid
import time
from .oracle import ScenarioOracle


class ScenarioBlastRadius(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class ScenarioStep:
    step_id: str
    sequence_order: int
    technique_id: str
    action_type: str  # emit_telemetry, probe_port, execute_command, mutate_config
    parameters: Dict[str, Any] = field(default_factory=dict)
    pause_seconds_after: float = 0.5
    stop_on_failure: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "sequence_order": self.sequence_order,
            "technique_id": self.technique_id,
            "action_type": self.action_type,
            "parameters": self.parameters,
            "pause_seconds_after": self.pause_seconds_after,
            "stop_on_failure": self.stop_on_failure,
        }


@dataclass
class ValidationScenario:
    scenario_id: str
    name: str
    version: str
    description: str
    environment_type: str  # cyber_range, shadow_mode
    target_assets: List[str]
    adversary_profile_id: Optional[str]
    preconditions: List[str]
    steps: List[ScenarioStep]
    oracle: ScenarioOracle
    cleanup_actions: List[str] = field(default_factory=lambda: ["restore_original_state"])
    blast_radius: ScenarioBlastRadius = ScenarioBlastRadius.LOW
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    author_id: str = "security-engineer-01"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "environment_type": self.environment_type,
            "target_assets": self.target_assets,
            "adversary_profile_id": self.adversary_profile_id,
            "preconditions": self.preconditions,
            "steps": [s.to_dict() for s in self.steps],
            "oracle": self.oracle.to_dict(),
            "cleanup_actions": self.cleanup_actions,
            "blast_radius": self.blast_radius.value if isinstance(self.blast_radius, ScenarioBlastRadius) else self.blast_radius,
            "tags": self.tags,
            "created_at": self.created_at,
            "author_id": self.author_id,
        }


class ScenarioBuilder:
    """Fluent builder for constructing validation scenarios."""

    def __init__(self, scenario_id: Optional[str] = None):
        self._scenario_id = scenario_id or f"SCN-{uuid.uuid4().hex[:8].upper()}"
        self._name = "Adversary Validation Scenario"
        self._version = "1.0.0"
        self._description = ""
        self._environment_type = "cyber_range"
        self._target_assets: List[str] = []
        self._adversary_profile_id: Optional[str] = None
        self._preconditions: List[str] = ["target_exists", "telemetry_enabled", "rollback_available"]
        self._steps: List[ScenarioStep] = []
        self._oracle: Optional[ScenarioOracle] = None
        self._cleanup: List[str] = ["restore_original_state"]
        self._blast_radius: ScenarioBlastRadius = ScenarioBlastRadius.LOW
        self._tags: List[str] = []
        self._author_id: str = "analyst-01"

    def with_id(self, scenario_id: str) -> "ScenarioBuilder":
        self._scenario_id = scenario_id
        return self

    def with_name(self, name: str) -> "ScenarioBuilder":
        self._name = name
        return self

    def with_description(self, description: str) -> "ScenarioBuilder":
        self._description = description
        return self

    def with_targets(self, targets: List[str]) -> "ScenarioBuilder":
        self._target_assets = targets
        return self

    def with_adversary_profile(self, profile_id: str) -> "ScenarioBuilder":
        self._adversary_profile_id = profile_id
        return self

    def with_blast_radius(self, blast_radius: ScenarioBlastRadius) -> "ScenarioBuilder":
        self._blast_radius = blast_radius
        return self

    def add_step(self, technique_id: str, action_type: str = "emit_telemetry", parameters: Optional[Dict[str, Any]] = None, pause: float = 0.2) -> "ScenarioBuilder":
        step_idx = len(self._steps) + 1
        step = ScenarioStep(
            step_id=f"step-{step_idx}",
            sequence_order=step_idx,
            technique_id=technique_id,
            action_type=action_type,
            parameters=parameters or {},
            pause_seconds_after=pause,
        )
        self._steps.append(step)
        return self

    def with_oracle(self, oracle: ScenarioOracle) -> "ScenarioBuilder":
        self._oracle = oracle
        return self

    def with_tags(self, tags: List[str]) -> "ScenarioBuilder":
        self._tags = tags
        return self

    def build(self) -> ValidationScenario:
        if not self._oracle:
            self._oracle = ScenarioOracle(
                expected_telemetry=["tls_event"],
                expected_detections=["TLS-LEGACY-001"],
            )
        return ValidationScenario(
            scenario_id=self._scenario_id,
            name=self._name,
            version=self._version,
            description=self._description,
            environment_type=self._environment_type,
            target_assets=self._target_assets or ["MTA-07"],
            adversary_profile_id=self._adversary_profile_id,
            preconditions=self._preconditions,
            steps=self._steps,
            oracle=self._oracle,
            cleanup_actions=self._cleanup,
            blast_radius=self._blast_radius,
            tags=self._tags,
            author_id=self._author_id,
        )


class ScenarioRepository:
    """Stores active and historical scenarios."""

    def __init__(self):
        self._scenarios: Dict[str, ValidationScenario] = {}
        self._load_default_scenarios()

    def _load_default_scenarios(self):
        # Scenario 102: Certificate Regression Validation (from Component 3 & 77)
        scn_cert = (
            ScenarioBuilder("SCN-102")
            .with_name("Certificate Regression Validation")
            .with_description("Validates certificate change detection, case investigation, and response workflow on MTA-07")
            .with_targets(["MTA-07"])
            .with_adversary_profile("ADV-002")
            .with_blast_radius(ScenarioBlastRadius.MEDIUM)
            .add_step("TECH-CERT-001", action_type="emit_telemetry", parameters={"cert_id": "CERT-ROGUE-992"})
            .with_oracle(ScenarioOracle(
                expected_telemetry=["certificate_event", "x509_chain_event"],
                expected_detections=["CERT-CHANGE-001"],
                expected_case_created=True,
                expected_response_action="ROTATE_CERTIFICATE",
                expected_approval_required=True,
                expected_verification_criteria={"active_cert_valid": True},
            ))
            .with_tags(["certificates", "regression", "purple_team"])
            .build()
        )

        # Scenario 101: TLS Downgrade & Legacy Protocol Test
        scn_tls = (
            ScenarioBuilder("SCN-101")
            .with_name("TLS Protocol Downgrade Validation")
            .with_description("Validates detection of forced legacy TLS 1.0 connection attempts against primary mail gateway")
            .with_targets(["MTA-07"])
            .with_adversary_profile("ADV-001")
            .with_blast_radius(ScenarioBlastRadius.LOW)
            .add_step("TECH-042", action_type="emit_telemetry", parameters={"tls_version": "TLS 1.0", "ja4": "t10d0100h0_legacy_probe"})
            .with_oracle(ScenarioOracle(
                expected_telemetry=["tls_event", "ja4_event"],
                expected_detections=["TLS-LEGACY-001"],
                expected_case_created=True,
                expected_response_action="ISOLATE_HOST",
                expected_approval_required=False,
                expected_verification_criteria={"legacy_tls_sessions_wire": 0},
            ))
            .with_tags(["tls", "downgrade", "protocol"])
            .build()
        )

        # Scenario 103: STARTTLS Stripping Attack Validation
        scn_starttls = (
            ScenarioBuilder("SCN-103")
            .with_name("STARTTLS Stripping & Credential Exposure Validation")
            .with_description("Validates detection of stripped STARTTLS followed by plaintext SMTP authentication attempt")
            .with_targets(["MTA-02"])
            .with_adversary_profile("ADV-004")
            .with_blast_radius(ScenarioBlastRadius.HIGH)
            .add_step("TECH-STARTTLS-001", action_type="emit_telemetry")
            .add_step("TECH-CRED-001", action_type="emit_telemetry")
            .with_oracle(ScenarioOracle(
                expected_telemetry=["smtp_ehlo_event", "smtp_auth_event"],
                expected_detections=["STARTTLS-STRIP-001", "AUTH-PLAINTEXT-001"],
                expected_case_created=True,
                expected_response_action="REVOKE_CREDENTIALS",
                expected_approval_required=True,
            ))
            .with_tags(["starttls", "credentials", "smtp"])
            .build()
        )

        # Scenario 104: PQC Cryptographic Agility Validation
        scn_pqc = (
            ScenarioBuilder("SCN-104")
            .with_name("Post-Quantum Cryptographic Regression Validation")
            .with_description("Validates detection when ML-KEM/Kyber hybrid key exchange is unexpectedly stripped")
            .with_targets(["MTA-PQC-01"])
            .with_adversary_profile("ADV-005")
            .with_blast_radius(ScenarioBlastRadius.LOW)
            .add_step("TECH-CRYPTO-PQC-001", action_type="emit_telemetry")
            .with_oracle(ScenarioOracle(
                expected_telemetry=["tls_kex_event"],
                expected_detections=["PQC-DOWNGRADE-001"],
                expected_case_created=True,
                expected_response_action="ALERT_CRYPTO_TEAM",
                expected_approval_required=False,
            ))
            .with_tags(["pqc", "quantum", "crypto_agility"])
            .build()
        )

        for s in [scn_cert, scn_tls, scn_starttls, scn_pqc]:
            self._scenarios[s.scenario_id] = s

    def get(self, scenario_id: str) -> Optional[ValidationScenario]:
        return self._scenarios.get(scenario_id)

    def list_all(self) -> List[ValidationScenario]:
        return list(self._scenarios.values())

    def save(self, scenario: ValidationScenario) -> None:
        self._scenarios[scenario.scenario_id] = scenario
