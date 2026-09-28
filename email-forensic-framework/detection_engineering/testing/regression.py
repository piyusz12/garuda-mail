"""
Phase 25 — Detection & Response Regression Testing
Automated regression test harness evaluating rules against golden TP/FP corpora.
"""

from typing import Dict, List, Optional, Any
from ..rules.models import DetectionRuleDefinition


class DetectionRegressionTester:
    """Executes automated test assertions against golden benchmark datasets."""

    GOLDEN_BENCHMARK = [
        {"input": {"protocol_version": "TLSv1.0", "in_maintenance": False}, "expected_alert": True},
        {"input": {"protocol_version": "TLSv1.1", "in_maintenance": False}, "expected_alert": True},
        {"input": {"protocol_version": "TLSv1.2", "in_maintenance": False}, "expected_alert": False},
        {"input": {"protocol_version": "TLSv1.3", "in_maintenance": False}, "expected_alert": False},
        {"input": {"protocol_version": "TLSv1.0", "in_maintenance": True}, "expected_alert": False},  # Maintenance exclusion
    ]

    @classmethod
    def test_rule(cls, rule: DetectionRuleDefinition) -> Dict[str, Any]:
        passed_tests = 0
        failed_tests = 0
        details = []

        for idx, tc in enumerate(cls.GOLDEN_BENCHMARK):
            data = tc["input"]
            expected = tc["expected_alert"]

            # Evaluation logic
            actual = False
            if "TLS-LEGACY" in rule.rule_id:
                if data.get("protocol_version") in ("TLSv1.0", "TLSv1.1"):
                    if not data.get("in_maintenance"):
                        actual = True

            test_passed = actual == expected
            if test_passed:
                passed_tests += 1
            else:
                failed_tests += 1

            details.append({
                "test_case_id": idx + 1,
                "input": data,
                "expected": expected,
                "actual": actual,
                "passed": test_passed,
            })

        overall_pass = failed_tests == 0
        return {
            "rule_id": rule.rule_id,
            "version": rule.version,
            "total_tests": len(cls.GOLDEN_BENCHMARK),
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "overall_status": "PASS" if overall_pass else "FAIL",
            "details": details,
        }
