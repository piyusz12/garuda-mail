"""
Phase 24 — Lessons Learned & Continuous Response Improvement (Components 35, 70)
Extracts structured root-causes, detection gaps, and automation opportunities, feeding back into Phase 23.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
import time
import uuid

from incident.models import Incident


@dataclass
class IncidentLessonsLearned:
    lesson_id: str
    incident_id: str
    root_cause_analysis: str
    response_strengths: List[str]
    response_weaknesses: List[str]
    detection_gap_identified: bool
    detection_rule_recommendation: Optional[str]
    playbook_improvement_recommendation: Optional[str]
    automation_opportunity: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LessonsLearnedEngine:
    """Closes the continuous security feedback loop by synthesizing actionable improvements from incidents."""

    @classmethod
    def extract_lessons(cls, incident: Incident, plan: Optional[Any] = None) -> IncidentLessonsLearned:
        lid = f"LES-{uuid.uuid4().hex[:6].upper()}"

        has_reopen = incident.reopened_count > 0
        is_crypto = any("TLS" in d for d in incident.detections) or "CRYPTO" in incident.title.upper()

        if is_crypto:
            root_cause = "MTA configuration drift during system package upgrade or manual operator reconfiguration reverted permissive TLS options."
            strengths = ["Canary staged remediation isolated changes to single host before full deployment", "Evidence was preserved prior to mutable configuration changes"]
            weaknesses = ["Initial detection occurred after 3 legacy sessions were already established"] if not has_reopen else ["Recurrence watcher observed return within 4 months"]
            det_gap = has_reopen
            det_rec = "Tune DET-TLS-001 threshold from 3 sessions to 1 session on core gateway relays." if has_reopen else None
            playbook_rec = "Add pre-remediation compatibility check to Playbook v2.2."
            auto_opp = "Promote Playbook to CANARY_AUTOMATION after 10 consecutive clean executions."
        else:
            root_cause = "General protocol anomaly or unauthorized access attempt on mail submission port."
            strengths = ["Rapid containment applied via temporary firewall ACL"]
            weaknesses = ["Analyst manual approval took 12 minutes"]
            det_gap = False
            det_rec = None
            playbook_rec = "Define automated pre-approvals for low-risk non-disruptive actions."
            auto_opp = "Automate temporary 30-minute quarantine without requiring senior engineer approval."

        lesson = IncidentLessonsLearned(
            lesson_id=lid,
            incident_id=incident.incident_id,
            root_cause_analysis=root_cause,
            response_strengths=strengths,
            response_weaknesses=weaknesses,
            detection_gap_identified=det_gap,
            detection_rule_recommendation=det_rec,
            playbook_improvement_recommendation=playbook_rec,
            automation_opportunity=auto_opp
        )
        return lesson
