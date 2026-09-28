"""
Copilot Reporting & Executive Narrative Synthesizer.
Transforms raw telemetry, detection stats, and gap metrics into crisp executive briefings.
"""
from typing import Dict, List, Optional, Any
from validation.evaluation.metrics import ValidationScorecard, LatencyMetrics


class CopilotReporting:
    """Synthesizes executive and SOC operational reports."""

    @staticmethod
    def generate_executive_briefing(scorecard: ValidationScorecard, latencies: LatencyMetrics) -> str:
        s = scorecard
        l = latencies

        summary_lines = [
            "================================================================================",
            "                   CONTINUOUS SECURITY VALIDATION EXECUTIVE BRIEFING",
            "================================================================================",
            f"Overall Status:        {'HEALTHY & RESILIENT' if s.critical_gaps_count == 0 else 'DEFENSIVE GAPS DETECTED'}",
            f"Total Scenarios Run:   {s.total_scenarios_evaluated} (Passed: {s.passed_scenarios} | Partial: {s.partial_scenarios} | Failed: {s.failed_scenarios})",
            "--------------------------------------------------------------------------------",
            "MULTI-DIMENSIONAL DEFENSIVE SCORECARD:",
            f"  - Telemetry Visibility:    {s.visibility_pct}%",
            f"  - Detection Rate:          {s.detection_pct}%",
            f"  - Incident Triage:         {s.triage_pct}%",
            f"  - Automated Investigation: {s.investigation_pct}%",
            f"  - Remediation Response:    {s.response_pct}%",
            f"  - Post-Action Verification:{s.verification_pct}%",
            f"  - System Recovery:         {s.recovery_pct}%",
            "--------------------------------------------------------------------------------",
            "OPERATIONAL LATENCIES (MEAN TIME TO RESPOND):",
            f"  - TTV (Time to Visibility):   {l.ttv_avg_sec}s",
            f"  - TTD (Time to Detection):    {l.ttd_avg_sec}s",
            f"  - TTA (Time to Acknowledge):  {l.tta_avg_sec}s",
            f"  - TTI (Time to Investigate):  {l.tti_avg_sec}s",
            f"  - TTR (Time to Respond):      {l.ttr_avg_sec}s",
            f"  - TTVR (Time to Verify):      {l.ttvr_avg_sec}s",
            "--------------------------------------------------------------------------------",
            f"Active Validation Gaps:  {s.open_validation_gaps_count} (Critical: {s.critical_gaps_count})",
            "================================================================================",
        ]
        return "\n".join(summary_lines)
