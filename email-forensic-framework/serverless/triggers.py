"""
Serverless Function Triggers and Event Sources.
Component 33: Catalogs function invocation sources, APIs, schedules, and event bridges.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class TriggerType(str, Enum):
    API_GATEWAY = "API_GATEWAY"
    S3_BUCKET = "S3_BUCKET"
    SNS_TOPIC = "SNS_TOPIC"
    EVENTBRIDGE = "EVENTBRIDGE"
    CRON_SCHEDULE = "CRON_SCHEDULE"
    KAFKA_STREAM = "KAFKA_STREAM"


@dataclass
class FunctionTrigger:
    trigger_id: str
    function_id: str
    trigger_type: TriggerType
    source_arn: str
    is_public: bool = False
    auth_required: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trigger_id": self.trigger_id,
            "function_id": self.function_id,
            "trigger_type": self.trigger_type.value if isinstance(self.trigger_type, TriggerType) else self.trigger_type,
            "source_arn": self.source_arn,
            "is_public": self.is_public,
            "auth_required": self.auth_required,
            "metadata": self.metadata,
        }
