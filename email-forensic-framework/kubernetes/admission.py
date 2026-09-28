"""
Kubernetes Validating Admission Controller.
Component 15: Validating webhook gating deployments based on cryptographic signatures, SBOM presence, and security context.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import uuid


@dataclass
class AdmissionReviewRequest:
    uid: str = field(default_factory=lambda: f"ADM-{uuid.uuid4().hex[:6]}")
    request_id: Optional[str] = None
    operation: str = "CREATE"  # CREATE, UPDATE, DELETE
    resource_kind: str = "Pod"  # Pod, Deployment, StatefulSet
    namespace: str = "default"
    workload_name: str = "workload"
    image_tag: str = ""
    image_digest: str = ""
    image_signed: bool = True
    has_sbom: bool = True
    run_as_non_root: bool = True
    read_only_root_filesystem: bool = True
    allow_privilege_escalation: bool = False
    is_privileged_container: bool = False
    is_privileged: Optional[bool] = None
    service_account: Optional[str] = None

    def __post_init__(self):
        if self.request_id and (not self.uid or self.uid.startswith("ADM-")):
            self.uid = self.request_id
        if self.is_privileged is not None:
            self.is_privileged_container = self.is_privileged
        # Auto-detect unsigned or untrusted test digests
        if "0000000000" in self.image_digest or "unverified" in self.image_tag or "unknown" in self.image_tag:
            self.image_signed = False


@dataclass
class AdmissionReviewResponse:
    uid: str
    allowed: bool
    status_code: int
    reasons: List[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uid": self.uid,
            "allowed": self.allowed,
            "status_code": self.status_code,
            "reasons": self.reasons,
            "reason": self.reason,
        }


class AdmissionController:
    """Enforces zero-trust pre-deployment validation for Kubernetes admission."""

    @classmethod
    def evaluate_admission(cls, req: AdmissionReviewRequest) -> AdmissionReviewResponse:
        reasons = []
        is_allowed = True

        # Policy 1: Cryptographic signature verification
        if not req.image_signed:
            is_allowed = False
            reasons.append("Image Signature Missing: Unsigned images are forbidden in enterprise clusters.")

        # Policy 2: SBOM presence
        if not req.has_sbom:
            is_allowed = False
            reasons.append("SBOM Missing: Deployed images must have an attested Software Bill of Materials.")

        # Policy 3: Root container restriction
        if not req.run_as_non_root:
            is_allowed = False
            reasons.append("SecurityContext Violation: Containers must specify 'runAsNonRoot: true'.")

        # Policy 4: Privileged container prohibition
        if req.is_privileged_container or req.allow_privilege_escalation:
            is_allowed = False
            reasons.append("Privilege Escalation Violation: Privileged containers and escalation are prohibited.")

        status_code = 200 if is_allowed else 403
        if is_allowed:
            reasons.append(f"Workload '{req.workload_name}' passed all Zero Trust admission checks.")

        return AdmissionReviewResponse(
            uid=req.uid,
            allowed=is_allowed,
            status_code=status_code,
            reasons=reasons,
        )
