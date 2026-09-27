"""
Phase 23 - Investigation Playbooks.
Defines reusable, deterministic step sequences for forensic investigations.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any

@dataclass
class PlaybookStep:
    step_num: int
    name: str
    action_type: str  # READ, SEARCH, CORRELATE, SUMMARIZE, PROPOSE
    description: str

@dataclass
class InvestigationPlaybook:
    playbook_id: str
    name: str
    trigger_condition: str
    steps: List[PlaybookStep]


INVESTIGATION_PLAYBOOKS: Dict[str, InvestigationPlaybook] = {
    "PB-CERT-01": InvestigationPlaybook(
        playbook_id="PB-CERT-01",
        name="Suspicious Certificate Change Investigation",
        trigger_condition="certificate_changed = true AND ja4_rarity < 0.05",
        steps=[
            PlaybookStep(1, "Identify Subject Certificate", "READ", "Extract certificate thumbprint, issuer, and validity period."),
            PlaybookStep(2, "Find Preceding Certificate", "SEARCH", "Query historical lakehouse for previous certificate on asset."),
            PlaybookStep(3, "Find Affected Mail Assets", "SEARCH", "Identify all MTAs presenting the same certificate thumbprint."),
            PlaybookStep(4, "Compare Certificate Cryptographic Parameters", "CORRELATE", "Analyze key length, signature algorithm, and SAN entries."),
            PlaybookStep(5, "Search Associated Client JA4s", "SEARCH", "Collect all client JA4 fingerprints observed during transition."),
            PlaybookStep(6, "Search Historical Incidents", "SEARCH", "Check if similar certificate anomalies occurred in past 2 years."),
            PlaybookStep(7, "Check Deployment Management Records", "SEARCH", "Verify whether change window was officially authorized."),
            PlaybookStep(8, "Synthesize Evidence Bundle", "PROPOSE", "Assemble reproducible evidence manifest and case candidate.")
        ]
    ),
    "PB-STARTTLS-01": InvestigationPlaybook(
        playbook_id="PB-STARTTLS-01",
        name="STARTTLS Downgrade Investigation",
        trigger_condition="starttls_stripped = true",
        steps=[
            PlaybookStep(1, "Inspect SMTP Handshake", "READ", "Parse 220 greeting and EHLO capabilities response."),
            PlaybookStep(2, "Verify Transition Rule", "CORRELATE", "Check if STARTTLS was advertised then stripped or timed out."),
            PlaybookStep(3, "Trace Network Intermediaries", "SEARCH", "Locate upstream MTA IPs and middlebox signatures."),
            PlaybookStep(4, "Check Historical Peer Baseline", "SEARCH", "Compare with peer connections to same recipient domain."),
            PlaybookStep(5, "Propose Mitigation", "PROPOSE", "Recommend MTA-STS or DANE enforcement.")
        ]
    )
}
