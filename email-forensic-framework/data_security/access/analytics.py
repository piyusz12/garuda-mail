"""
Data Minimization and Access Analytics Engine.
Components 29.23 & 29.24: Identifies over-privileged application queries and unnecessary sensitive column consumption.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from enum import Enum
import uuid
import time


class MinimizationFindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DataMinimizationFinding:
    finding_id: str
    service_id: str
    asset_id: str
    severity: MinimizationFindingSeverity
    declared_purpose_columns: List[str]
    actually_accessed_columns: List[str]
    unnecessary_columns: List[str]
    description: str
    remediation: str
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "service_id": self.service_id,
            "asset_id": self.asset_id,
            "severity": self.severity.value,
            "declared_purpose_columns": self.declared_purpose_columns,
            "actually_accessed_columns": self.actually_accessed_columns,
            "unnecessary_columns": self.unnecessary_columns,
            "description": self.description,
            "remediation": self.remediation,
            "detected_at": self.detected_at,
        }


class DataMinimizationAnalyzer:
    """Analyzes SQL/API read queries against declared least-privilege schemas."""

    def __init__(self):
        # service_id -> asset_id -> set of declared columns
        self._declared_contracts: Dict[str, Dict[str, Set[str]]] = {}
        self._seed_default_contracts()

    def _seed_default_contracts(self):
        # MTA service only needs customer_id and email for relay delivery
        self.register_contract(
            service_id="MTA-07",
            asset_id="DATA-8821",
            necessary_columns={"customer_id", "email"},
        )

    def register_contract(self, service_id: str, asset_id: str, necessary_columns: Set[str]) -> None:
        if service_id not in self._declared_contracts:
            self._declared_contracts[service_id] = {}
        self._declared_contracts[service_id][asset_id] = necessary_columns

    def audit_query_access(
        self,
        service_id: str,
        asset_id: str,
        requested_columns: List[str],
    ) -> Optional[DataMinimizationFinding]:
        contracts = self._declared_contracts.get(service_id, {})
        allowed_cols = contracts.get(asset_id)

        if not allowed_cols:
            # No registered contract; flag uncontracted data access
            return DataMinimizationFinding(
                finding_id=f"MIN-{uuid.uuid4().hex[:8].upper()}",
                service_id=service_id,
                asset_id=asset_id,
                severity=MinimizationFindingSeverity.MEDIUM,
                declared_purpose_columns=[],
                actually_accessed_columns=requested_columns,
                unnecessary_columns=requested_columns,
                description=f"Service {service_id} accessed dataset {asset_id} without a registered data minimization contract.",
                remediation="Declare explicit required schema columns for this service.",
            )

        req_set = set(requested_columns)
        excessive = req_set - allowed_cols

        if excessive:
            has_sensitive = any(c in ["payment_token", "billing_address", "phone", "ssn"] for c in excessive)
            severity = MinimizationFindingSeverity.HIGH if has_sensitive else MinimizationFindingSeverity.MEDIUM

            return DataMinimizationFinding(
                finding_id=f"MIN-{uuid.uuid4().hex[:8].upper()}",
                service_id=service_id,
                asset_id=asset_id,
                severity=severity,
                declared_purpose_columns=sorted(list(allowed_cols)),
                actually_accessed_columns=sorted(list(req_set)),
                unnecessary_columns=sorted(list(excessive)),
                description=f"EXCESSIVE_DATA_ACCESS: Service {service_id} requested unnecessary sensitive columns {sorted(list(excessive))} from {asset_id}.",
                remediation=f"Refactor service {service_id} queries to only select {sorted(list(allowed_cols))}.",
            )

        return None
