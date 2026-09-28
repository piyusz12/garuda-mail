"""
API Security Inventory and Catalog.
Component 31: Discovers and tracks API services, endpoints, methods, auth types, and data sensitivity.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class AuthType(str, Enum):
    MTLS = "mTLS"
    JWT_BEARER = "JWT_BEARER"
    API_KEY = "API_KEY"
    NONE = "NONE"


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


@dataclass
class APIEndpoint:
    endpoint_id: str
    service_id: str
    path: str
    method: str
    auth_type: AuthType
    data_classification: DataClassification = DataClassification.INTERNAL
    rate_limit_rpm: int = 1200
    is_deprecated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "service_id": self.service_id,
            "path": self.path,
            "method": self.method,
            "auth_type": self.auth_type.value if isinstance(self.auth_type, AuthType) else self.auth_type,
            "data_classification": self.data_classification.value if isinstance(self.data_classification, DataClassification) else self.data_classification,
            "rate_limit_rpm": self.rate_limit_rpm,
            "is_deprecated": self.is_deprecated,
            "metadata": self.metadata,
        }


class APIRegistry:
    """Enterprise API inventory and discovery repository."""

    def __init__(self):
        self._endpoints: Dict[str, APIEndpoint] = {}
        self._seed_default_apis()

    def _seed_default_apis(self) -> None:
        """Seed core platform API endpoints."""
        endpoints = [
            APIEndpoint(
                endpoint_id="API-CERT-01",
                service_id="MTA-07",
                path="/api/certificates",
                method="POST",
                auth_type=AuthType.MTLS,
                data_classification=DataClassification.CONFIDENTIAL,
                rate_limit_rpm=600,
            ),
            APIEndpoint(
                endpoint_id="API-FORENSIC-01",
                service_id="FORENSIC-API",
                path="/api/v1/cases/evidence",
                method="GET",
                auth_type=AuthType.JWT_BEARER,
                data_classification=DataClassification.RESTRICTED,
                rate_limit_rpm=300,
            ),
            APIEndpoint(
                endpoint_id="API-TELEMETRY-01",
                service_id="SENSOR-FABRIC",
                path="/api/v1/telemetry/ingest",
                method="POST",
                auth_type=AuthType.MTLS,
                data_classification=DataClassification.INTERNAL,
                rate_limit_rpm=10000,
            ),
            APIEndpoint(
                endpoint_id="API-PUBLIC-HEALTH",
                service_id="MTA-07",
                path="/healthz",
                method="GET",
                auth_type=AuthType.NONE,
                data_classification=DataClassification.PUBLIC,
                rate_limit_rpm=6000,
            ),
        ]
        for ep in endpoints:
            self.register_endpoint(ep)

    def register_endpoint(self, endpoint: APIEndpoint) -> None:
        self._endpoints[endpoint.endpoint_id] = endpoint

    def get_endpoint(self, endpoint_id: str) -> Optional[APIEndpoint]:
        return self._endpoints.get(endpoint_id)

    def list_endpoints(self) -> List[APIEndpoint]:
        return list(self._endpoints.values())

    def find_by_service(self, service_id: str) -> List[APIEndpoint]:
        return [ep for ep in self._endpoints.values() if ep.service_id == service_id]
