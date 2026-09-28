"""Tests for Adversary Model, Techniques, Scenario Builder, Parser, and Mutation."""
import pytest
from validation.adversary import (
    AdversaryProfileRepository,
    TechniqueLibrary,
    TechniqueCategory,
)
from validation.scenarios import (
    ScenarioBuilder,
    ScenarioRepository,
    ScenarioParser,
    ScenarioOracle,
    ScenarioBlastRadius,
    ScenarioMutationEngine,
)


def test_adversary_profiles_and_techniques():
    repo = AdversaryProfileRepository()
    profiles = repo.list_all()
    assert len(profiles) >= 5

    adv_cert = repo.get("ADV-002")
    assert adv_cert is not None
    assert "TECH-CERT-001" in adv_cert.technique_ids

    tech_lib = TechniqueLibrary()
    techs = tech_lib.list_all()
    assert len(techs) >= 7

    cert_techs = tech_lib.filter_by_category(TechniqueCategory.CERTIFICATES)
    assert len(cert_techs) >= 2
    assert any(t.technique_id == "TECH-CERT-001" for t in cert_techs)


def test_scenario_builder_and_oracle():
    builder = (
        ScenarioBuilder("SCN-TEST-01")
        .with_name("TLS Anomaly Test")
        .with_description("Unit test scenario")
        .with_targets(["MTA-07"])
        .add_step("TECH-042", action_type="emit_telemetry", parameters={"tls_version": "TLS 1.0"})
        .with_oracle(ScenarioOracle(
            expected_telemetry=["tls_event"],
            expected_detections=["TLS-LEGACY-001"],
            expected_response_action="ISOLATE_HOST",
        ))
        .with_blast_radius(ScenarioBlastRadius.LOW)
    )
    scn = builder.build()
    assert scn.scenario_id == "SCN-TEST-01"
    assert len(scn.steps) == 1
    assert scn.oracle.expected_detections == ["TLS-LEGACY-001"]
    assert scn.blast_radius == ScenarioBlastRadius.LOW

    # Serialization test
    d = scn.to_dict()
    assert d["scenario_id"] == "SCN-TEST-01"
    assert d["blast_radius"] == "LOW"


def test_scenario_yaml_parser():
    yaml_text = """
scenario_id: SCN-YAML-01
name: YAML Parser Test
target_assets:
  - MTA-02
blast_radius: MEDIUM
steps:
  - step_id: s1
    sequence_order: 1
    technique_id: TECH-STARTTLS-001
    action_type: emit_telemetry
oracle:
  expected_telemetry:
    - smtp_ehlo_event
  expected_detections:
    - STARTTLS-STRIP-001
  expected_response_action: ENFORCE_MTA_STS
"""
    scn = ScenarioParser.parse_yaml(yaml_text)
    assert scn.scenario_id == "SCN-YAML-01"
    assert scn.target_assets == ["MTA-02"]
    assert scn.blast_radius == ScenarioBlastRadius.MEDIUM
    assert scn.steps[0].technique_id == "TECH-STARTTLS-001"
    assert scn.oracle.expected_detections == ["STARTTLS-STRIP-001"]


def test_scenario_mutation_engine():
    repo = ScenarioRepository()
    base_scn = repo.get("SCN-101")
    assert base_scn is not None

    family = ScenarioMutationEngine.generate_family(base_scn, count=3)
    assert len(family) == 3
    for idx, mutant in enumerate(family):
        assert mutant.scenario_id == f"SCN-101-MUT-{idx+1}"
        assert "mutated" in mutant.tags
        assert mutant.steps[0].parameters.get("tls_version") in ("TLS 1.0", "TLS 1.1", "SSLv3")
