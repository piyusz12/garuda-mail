"""
Data Catalog Metadata and Compliance Tags.
Component 29.7: Enriches data assets with compliance frameworks (GDPR, PCI-DSS, HIPAA) and column descriptors.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ColumnMetadata:
    column_name: str
    data_type: str
    is_primary_key: bool = False
    is_nullable: bool = True
    contains_pii: bool = False
    pii_type: Optional[str] = None
    sample_hash: Optional[str] = None


@dataclass
class AssetComplianceProfile:
    asset_id: str
    applicable_frameworks: List[str] = field(default_factory=lambda: ["GDPR", "PCI-DSS"])
    data_residency_region: str = "us-east-1"
    cross_border_transfer_allowed: bool = False
    gdpr_legal_basis: str = "CONTRACTUAL_NECESSITY"
    retention_period_months: int = 24
