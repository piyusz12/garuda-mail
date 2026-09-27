"""
Phase 23 - Detection Versioning, Change Diffs, Tuning Auditing, and Promotion Pipeline.
Enforces software engineering rigor on detection rules.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import copy
from .models import DetectionRule

@dataclass
class TuningAuditRecord:
    audit_id: str
    rule_id: str
    from_version: str
    to_version: str
    changed_by: str
    reason: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    diff: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)

@dataclass
class RuleVersionDiff:
    from_version: str
    to_version: str
    threshold_changes: Dict[str, Any]
    window_changes: Dict[str, Any]
    excluded_assets_added: List[str]
    excluded_assets_removed: List[str]
    logic_changes: Dict[str, Any]
    has_breaking_changes: bool


class DetectionVersioningEngine:
    """Maintains immutable history, diffs, audits, and promotion lifecycle."""

    PROMOTION_STAGES = ["DRAFT", "TEST", "VALIDATE", "STAGING", "CANARY", "PRODUCTION"]

    def __init__(self):
        # rule_id -> version_str -> DetectionRule
        self.versions: Dict[str, Dict[str, DetectionRule]] = {}
        # rule_id -> latest_version_str
        self.active_versions: Dict[str, str] = {}
        # Audit history list
        self.audit_log: List[TuningAuditRecord] = []

    def register_rule(self, rule: DetectionRule) -> DetectionRule:
        rule_id = rule.detection_id
        if rule_id not in self.versions:
            self.versions[rule_id] = {}
        self.versions[rule_id][rule.version] = copy.deepcopy(rule)
        self.active_versions[rule_id] = rule.version
        return rule

    def create_new_version(
        self,
        base_rule_id: str,
        new_version: str,
        updates: Dict[str, Any],
        author: str,
        reason: str,
        evidence: Optional[List[str]] = None
    ) -> DetectionRule:
        """Clones base rule, applies updates, computes diff, logs audit, and stores new immutable version."""
        if base_rule_id not in self.versions:
            raise ValueError(f"Rule {base_rule_id} not found")
        
        current_ver = self.active_versions[base_rule_id]
        base_rule = self.versions[base_rule_id][current_ver]

        # Create updated clone
        new_rule_dict = asdict(base_rule)
        new_rule_dict.update(updates)
        new_rule_dict["version"] = new_version
        new_rule_dict["updated_at"] = datetime.now(timezone.utc)
        new_rule_dict["status"] = "DRAFT"  # Reset to draft for safety pipeline

        # Reconstruct object
        from .models import SeverityDimensions
        if "severity_dimensions" in updates:
            new_rule_dict["severity_dimensions"] = SeverityDimensions(**updates["severity_dimensions"])
        else:
            new_rule_dict["severity_dimensions"] = base_rule.severity_dimensions

        new_rule = DetectionRule(**new_rule_dict)

        # Compute diff
        diff = self.compute_diff(base_rule, new_rule)
        audit = TuningAuditRecord(
            audit_id=f"AUDIT-{len(self.audit_log)+1:04d}",
            rule_id=base_rule_id,
            from_version=current_ver,
            to_version=new_version,
            changed_by=author,
            reason=reason,
            diff=asdict(diff),
            evidence_refs=evidence or []
        )
        self.audit_log.append(audit)

        self.versions[base_rule_id][new_version] = new_rule
        self.active_versions[base_rule_id] = new_version
        return new_rule

    def compute_diff(self, old_rule: DetectionRule, new_rule: DetectionRule) -> RuleVersionDiff:
        old_logic = old_rule.logic or {}
        new_logic = new_rule.logic or {}

        threshold_changes = {}
        for k in set(list(old_logic.keys()) + list(new_logic.keys())):
            if "threshold" in k or "rarity" in k or "count" in k:
                if old_logic.get(k) != new_logic.get(k):
                    threshold_changes[k] = {"from": old_logic.get(k), "to": new_logic.get(k)}

        window_changes = {}
        for k in ("window", "time_window", "within_seconds"):
            if old_logic.get(k) != new_logic.get(k):
                window_changes[k] = {"from": old_logic.get(k), "to": new_logic.get(k)}

        old_exclusions = set(old_logic.get("excluded_assets", []))
        new_exclusions = set(new_logic.get("excluded_assets", []))

        logic_changes = {}
        for k, v in new_logic.items():
            if old_logic.get(k) != v and k not in threshold_changes and k not in window_changes:
                logic_changes[k] = {"from": old_logic.get(k), "to": v}

        breaking = old_rule.rule_type != new_rule.rule_type or len(threshold_changes) > 1

        return RuleVersionDiff(
            from_version=old_rule.version,
            to_version=new_rule.version,
            threshold_changes=threshold_changes,
            window_changes=window_changes,
            excluded_assets_added=list(new_exclusions - old_exclusions),
            excluded_assets_removed=list(old_exclusions - new_exclusions),
            logic_changes=logic_changes,
            has_breaking_changes=breaking
        )

    def promote_rule(self, rule_id: str, target_stage: str, canary_assets: Optional[List[str]] = None) -> DetectionRule:
        """Promotes a detection along the DRAFT -> TEST -> VALIDATE -> STAGING -> CANARY -> PRODUCTION pipeline."""
        target_stage = target_stage.upper()
        if target_stage not in self.PROMOTION_STAGES:
            raise ValueError(f"Invalid stage '{target_stage}'. Must be one of {self.PROMOTION_STAGES}")

        ver = self.active_versions.get(rule_id)
        if not ver:
            raise ValueError(f"No active rule version for {rule_id}")
        
        rule = self.versions[rule_id][ver]
        curr_idx = self.PROMOTION_STAGES.index(rule.status) if rule.status in self.PROMOTION_STAGES else -1
        target_idx = self.PROMOTION_STAGES.index(target_stage)

        if target_idx > curr_idx + 1:
            raise ValueError(f"Illegal jump in promotion pipeline: cannot promote directly from {rule.status} to {target_stage}. Must proceed step-wise.")

        rule.status = target_stage
        rule.updated_at = datetime.now(timezone.utc)
        if target_stage == "CANARY":
            rule.canary_target_assets = canary_assets or ["MTA-CANARY-01"]
        elif target_stage == "PRODUCTION":
            rule.canary_target_assets = []

        return rule

    def get_rule(self, rule_id: str, version: Optional[str] = None) -> Optional[DetectionRule]:
        if rule_id not in self.versions:
            return None
        ver = version or self.active_versions.get(rule_id)
        return self.versions[rule_id].get(ver)

    def list_all_active(self) -> List[DetectionRule]:
        return [self.versions[rid][ver] for rid, ver in self.active_versions.items()]
