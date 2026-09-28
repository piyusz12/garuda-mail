"""
Contextual Vulnerability Prioritization.
Component 38: Prioritizes CVEs factoring in runtime presence, internet reachability, and asset criticality.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class VulnerabilityFinding:
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    cvss_base_score: float = 5.0  # 0.0 to 10.0
    base_cvss: Optional[float] = None
    is_runtime_loaded: bool = False
    is_internet_exposed: bool = False
    service_criticality: str = "MEDIUM"
    has_public_exploit: bool = False
    description: str = ""

    def __post_init__(self):
        if self.base_cvss is not None:
            self.cvss_base_score = self.base_cvss

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "cvss_base_score": self.cvss_base_score,
            "has_public_exploit": self.has_public_exploit,
            "is_runtime_loaded": self.is_runtime_loaded,
            "is_internet_exposed": self.is_internet_exposed,
            "service_criticality": self.service_criticality,
            "description": self.description,
        }


class VulnerabilityScore(float):
    def __new__(cls, val, info):
        obj = super().__new__(cls, val)
        obj.info = info
        return obj

    def __getitem__(self, item):
        return self.info[item]

    def get(self, item, default=None):
        return self.info.get(item, default)

    def to_dict(self):
        return self.info


class VulnerabilityPrioritizer:
    """Calculates operational priority for vulnerabilities in running workloads."""

    @classmethod
    def calculate_priority_score(
        cls,
        vuln: VulnerabilityFinding,
        is_workload_running: Optional[bool] = None,
        is_internet_exposed: Optional[bool] = None,
        is_asset_critical: Optional[bool] = None,
    ) -> Any:
        """
        Calculates adjusted risk score based on real-world exposure:
        Score = Base CVSS * RuntimeMult * ExposureMult * CriticalityMult
        """
        running = is_workload_running if is_workload_running is not None else vuln.is_runtime_loaded
        exposed = is_internet_exposed if is_internet_exposed is not None else vuln.is_internet_exposed
        critical = is_asset_critical if is_asset_critical is not None else (vuln.service_criticality.upper() == "CRITICAL")

        score = vuln.cvss_base_score

        # Multipliers
        runtime_mult = 1.4 if running else 0.5
        exposure_mult = 1.5 if exposed else 0.8
        criticality_mult = 1.3 if critical else 1.0
        exploit_mult = 1.5 if vuln.has_public_exploit else 1.0

        adjusted = score * runtime_mult * exposure_mult * criticality_mult * exploit_mult
        adjusted = min(100.0, round(adjusted * 3.5, 1))  # Scale to 0-100

        if adjusted >= 80.0:
            priority = "IMMEDIATE_ACTION"
        elif adjusted >= 60.0:
            priority = "HIGH"
        elif adjusted >= 35.0:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        info = {
            "cve_id": vuln.cve_id,
            "package": vuln.package_name,
            "base_cvss": vuln.cvss_base_score,
            "adjusted_risk_score": adjusted,
            "operational_priority": priority,
            "factors": {
                "running_workload": running,
                "internet_exposed": exposed,
                "critical_asset": critical,
                "public_exploit": vuln.has_public_exploit,
            },
        }
        return VulnerabilityScore(adjusted, info)
