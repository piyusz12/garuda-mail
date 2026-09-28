"""
Unit & Integration Tests for Phase 28 API & Serverless Modules.
Tests API Catalog, mTLS Authentication Enforcement, Serverless Functions, and Trigger Auditing.
"""
import pytest
from api_security.inventory import APIEndpoint, APIRegistry, AuthType, DataClassification
from api_security.behavior import APIAccessEvent, APIBaseline
from api_security.detection import APISecurityDetector, APIAnomalySeverity
from serverless.functions import ServerlessFunction, FunctionRepository
from serverless.triggers import FunctionTrigger, TriggerType
from serverless.permissions import ServerlessPermissionAuditor, ServerlessFindingSeverity


def test_api_security_unauthenticated_request_detection():
    detector = APISecurityDetector()

    # Protected endpoint called without auth header
    unauth_event = APIAccessEvent(
        event_id="API-EVT-01",
        endpoint_id="API-CERT-01",
        caller_identity="ANONYMOUS",
        caller_workload_id="WORKLOAD-UNKNOWN",
        client_ip="198.51.100.12",
        method="POST",
        status_code=401,
        response_time_ms=12.5,
        auth_header_present=False,
        mtls_verified=False,
    )
    findings = detector.inspect_access_event(unauth_event)
    assert len(findings) >= 1
    unauth_findings = [f for f in findings if f.category == "UNAUTHENTICATED_ACCESS_ATTEMPT"]
    assert len(unauth_findings) == 1
    assert unauth_findings[0].severity == APIAnomalySeverity.CRITICAL


def test_api_security_mtls_verification_failure():
    detector = APISecurityDetector()

    # mTLS required endpoint called with JWT but without valid mTLS cert
    failed_mtls_event = APIAccessEvent(
        event_id="API-EVT-02",
        endpoint_id="API-CERT-01",
        caller_identity="USER-1192",
        caller_workload_id="WORKLOAD-991",
        client_ip="10.0.1.5",
        method="POST",
        status_code=403,
        response_time_ms=18.0,
        auth_header_present=True,
        mtls_verified=False,  # Failed client cert
    )
    findings = detector.inspect_access_event(failed_mtls_event)
    assert any(f.category == "MTLS_VERIFICATION_FAILURE" for f in findings)


def test_serverless_permission_auditor_overprivileged_role():
    auditor = ServerlessPermissionAuditor()
    overprivileged_fn = ServerlessFunction(
        function_id="FN-TEST-01",
        name="test-danger-fn",
        runtime="python3.11",
        handler="app.handler",
        execution_role_arn="arn:aws:iam::123456789012:role/AdministratorBroadAccessRole",
        environment_variables={"DATABASE_PASSWORD": "supersecretpassword123"},
        tags={"Environment": "production"},
        is_vpc_connected=False,
    )
    public_trigger = FunctionTrigger(
        trigger_id="TRIG-01",
        function_id="FN-TEST-01",
        trigger_type=TriggerType.API_GATEWAY,
        source_arn="arn:aws:apigateway:us-east-1::/restapis/xyz",
        is_public=True,
        auth_required=False,
    )
    findings = auditor.audit_function(overprivileged_fn, triggers=[public_trigger])
    rule_ids = [f.rule_id for f in findings]

    assert "SERVERLESS_OVERPRIVILEGED_ROLE" in rule_ids
    assert "SERVERLESS_PLAINTEXT_SECRET" in rule_ids
    assert "SERVERLESS_OUTSIDE_VPC" in rule_ids
    assert "SERVERLESS_PUBLIC_UNAUTH_TRIGGER" in rule_ids
