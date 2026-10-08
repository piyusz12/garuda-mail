from ai_security.copilot import (
    AIInvestigationCopilot,
    ContextEngine,
    CopilotQuery,
    Evidence,
    Guardrails,
    Investigation,
    InvestigationIntent,
    Recommendation,
    classify_intent,
)


def test_intent_classification():
    query = CopilotQuery(
        query="Investigate suspicious activity involving MTA-07",
        tenant_id="TENANT-001",
        analyst_id="ANALYST-07",
    )
    assert classify_intent(query.query) == InvestigationIntent.INVESTIGATE


def test_context_engine_tenant_isolation():
    engine = ContextEngine()
    context = engine.build_context(
        query="Investigate MTA-07",
        tenant_id="TENANT-001",
        analyst_id="ANALYST-07",
        permissions=["read:incidents"],
    )
    assert context["tenant_id"] == "TENANT-001"
    assert context["entity_id"] == "MTA-07"
    assert "alerts" in context["artifacts"]

    denied = engine.build_context(
        query="Investigate MTA-07",
        tenant_id="TENANT-001",
        analyst_id="ANALYST-07",
        permissions=[],
    )
    assert denied["authorized"] is False


def test_guardrails_block_destructive_actions():
    guardrails = Guardrails()
    decision = guardrails.evaluate_action(
        action="block_ip",
        target="10.0.0.99",
        tenant_id="TENANT-001",
        analyst_id="ANALYST-07",
        role="SOC_ANALYST",
        permissions=["read:incidents", "recommend:response"],
    )
    assert decision["allowed"] is False
    assert "approval" in decision["reason"].lower()


def test_evidence_and_recommendation_format():
    evidence = Evidence(
        evidence_id="E-001",
        category="TLS",
        description="STARTTLS downgrade detected",
        confidence=0.98,
        source="tls_events",
        references=["MTA-07"],
    )
    recommendation = Recommendation(
        recommendation_id="REC-001",
        case_id="CASE-1042",
        target="MTA-07",
        recommended_action="QUARANTINE_ASSET",
        reason=["STARTTLS downgrade detected"],
        risk_class="R3_POTENTIAL_IMPACT",
        requires_approval=True,
        rollback_available=True,
    )

    assert evidence.evidence_id == "E-001"
    assert recommendation.requires_approval is True


def test_hunt_generation_and_investigation_flow():
    copilot = AIInvestigationCopilot()
    response = copilot.investigate(
        "Investigate suspicious connection from MTA-07",
        tenant_id="TENANT-001",
        analyst_id="ANALYST-07",
        role="SOC_ANALYST",
        permissions=["read:incidents", "read:sessions", "read:alerts"],
    )

    assert response.intent == InvestigationIntent.INVESTIGATE
    assert response.risk_level in {"HIGH", "CRITICAL"}
    assert response.requires_approval is True
    assert response.evidence
    assert response.timeline

    hunt_query = copilot.generate_hunt_query("Find all rare JA4 fingerprints associated with legacy TLS in the last 90 days")
    assert "rare_ja4_legacy_tls" in hunt_query
    assert "90d" in hunt_query
