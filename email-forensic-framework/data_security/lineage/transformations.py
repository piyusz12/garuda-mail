"""
Data Lineage Transformations and Derivations.
Components 29.8 & 29.19: Tracks ETL pipelines, data masking, tokenization, and dataset aggregations.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class TransformationType(str, Enum):
    ETL_PIPELINE = "ETL_PIPELINE"
    TOKENIZATION = "TOKENIZATION"
    ANONYMIZATION = "ANONYMIZATION"
    AGGREGATION = "AGGREGATION"
    REPLICATION = "REPLICATION"
    EXPORT = "EXPORT"


@dataclass
class DataTransformation:
    transformation_id: str
    pipeline_name: str
    transformation_type: TransformationType
    source_asset_ids: List[str]
    target_asset_ids: List[str]
    applied_rules: List[str] = field(default_factory=list)
    operator_identity: str = "pipeline-runner@garuda.enterprise"
    is_active: bool = True
    last_run_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transformation_id": self.transformation_id,
            "pipeline_name": self.pipeline_name,
            "transformation_type": self.transformation_type.value,
            "source_asset_ids": self.source_asset_ids,
            "target_asset_ids": self.target_asset_ids,
            "applied_rules": self.applied_rules,
            "operator_identity": self.operator_identity,
            "is_active": self.is_active,
            "last_run_at": self.last_run_at,
        }
