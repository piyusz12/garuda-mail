"""
Phase 23 - MITRE ATT&CK Mapping.
Maps forensic detection rules and hunt findings to ATT&CK tactics, techniques, and sub-techniques.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

@dataclass
class MitreAttackMapping:
    tactic: str
    technique_id: str
    technique_name: str
    sub_technique: Optional[str]
    mapped_detection_ids: List[str]
    coverage_level: str  # HIGH, MEDIUM, PARTIAL, NONE


MITRE_ATTACK_CATALOG: Dict[str, MitreAttackMapping] = {
    "T1573.002": MitreAttackMapping(
        tactic="Command and Control",
        technique_id="T1573",
        technique_name="Encrypted Channel: Asymmetric Cryptography",
        sub_technique="T1573.002",
        mapped_detection_ids=["DET-TLS-001", "DET-221"],
        coverage_level="HIGH"
    ),
    "T1040": MitreAttackMapping(
        tactic="Credential Access",
        technique_id="T1040",
        technique_name="Network Sniffing",
        sub_technique=None,
        mapped_detection_ids=["DET-STARTTLS-001"],
        coverage_level="MEDIUM"
    ),
    "T1562.001": MitreAttackMapping(
        tactic="Defense Evasion",
        technique_id="T1562",
        technique_name="Impair Defenses: Disable or Modify Tools",
        sub_technique="T1562.001",
        mapped_detection_ids=["DET-CIPHER-001", "DET-CERT-001"],
        coverage_level="HIGH"
    )
}
