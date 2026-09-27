"""
Tests for Phase 23 Threat Hunting Engine, DSL Parser, Planner, and Scheduler.
"""
import pytest
from datetime import datetime, timezone

from hunting.dsl import HQLParser, HuntQueryAST
from hunting.planner import HuntQueryPlanner
from hunting.templates import HUNT_TEMPLATES
from hunting.scheduler import HuntScheduler
from hunting.engine import ThreatHuntingEngine

def test_hql_parser():
    query = "HUNT suspicious_cert FROM tls_events WHERE certificate.changed = true AND ja4.rarity < 0.05 WITHIN 7d"
    ast = HQLParser.parse(query)
    assert ast.hunt_name == "suspicious_cert"
    assert ast.source_entity == "tls_events"
    assert ast.within_window == "7d"
    assert len(ast.conditions) == 2

    # Query with IN list
    query_in = "HUNT legacy_tls FROM tls_events WHERE tls.version IN ['TLS 1.0', 'TLS 1.1'] WITHIN 90d"
    ast_in = HQLParser.parse(query_in)
    assert ast_in.conditions[0].operator == "IN"
    assert "tls 1.0" in [x.lower() for x in ast_in.conditions[0].value]

def test_hunt_query_planner():
    query = "HUNT deep_historical FROM tls_events WHERE rarity < 0.01 WITHIN 90d"
    ast = HQLParser.parse(query)
    plan = HuntQueryPlanner.create_plan(ast)
    assert plan.hunt_name == "deep_historical"
    assert "SILVER" in plan.target_layers
    assert plan.target_entity == "SESSION"
    assert plan.time_cutoff is not None
    assert plan.estimated_cost_units > 10

def test_hunt_scheduler():
    scheduler = HuntScheduler()
    entry = scheduler.schedule_hunt("test_hunt", "HUNT test FROM tls_events", "hourly")
    assert entry.schedule_type == "hourly"
    assert entry.is_active is True

    # Record run
    run = scheduler.record_run("test_hunt", "HUNT test FROM tls_events", "24h", 5, 12.5, 15, datetime.now(timezone.utc))
    assert run.results_count == 5
    assert len(scheduler.run_history) == 1

def test_hunt_templates_catalog():
    assert len(HUNT_TEMPLATES) >= 10
    tmpl = HUNT_TEMPLATES["HUNT-TMPL-01"]
    assert "legacy_tls_recurrence" in tmpl.hql_query
    assert tmpl.recommended_schedule != ""

def test_autonomous_hunt_proposal():
    engine = ThreatHuntingEngine()
    anomalies = [
        {"asset": "MTA-07", "ja4": "JA4-ROGUE"},
        {"asset": "MTA-08", "ja4": "JA4-ROGUE"}
    ]
    proposal = engine.propose_autonomous_hunt(anomalies)
    assert proposal is not None
    assert "autonomous_investigation" in proposal["query"]
    assert len(proposal["target_assets"]) == 2
