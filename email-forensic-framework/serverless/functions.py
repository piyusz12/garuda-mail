"""
Serverless Functions Inventory and Catalog.
Component 33: Catalogs serverless functions, execution roles, environment config, and hash integrity.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ServerlessFunction:
    function_id: str
    name: str
    runtime: str
    handler: str
    execution_role_arn: str
    memory_mb: int = 256
    timeout_seconds: int = 30
    is_vpc_connected: bool = True
    code_sha256: str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    environment_variables: Dict[str, str] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_id": self.function_id,
            "name": self.name,
            "runtime": self.runtime,
            "handler": self.handler,
            "execution_role_arn": self.execution_role_arn,
            "memory_mb": self.memory_mb,
            "timeout_seconds": self.timeout_seconds,
            "is_vpc_connected": self.is_vpc_connected,
            "code_sha256": self.code_sha256,
            "environment_variables": {k: "***" if "SECRET" in k or "KEY" in k else v for k, v in self.environment_variables.items()},
            "tags": self.tags,
        }


class FunctionRepository:
    """Manages inventory of deployed serverless functions."""

    def __init__(self):
        self._functions: Dict[str, ServerlessFunction] = {}
        self._seed_default_functions()

    def _seed_default_functions(self) -> None:
        fn1 = ServerlessFunction(
            function_id="FN-CERT-ROTATE",
            name="garuda-cert-auto-rotator",
            runtime="python3.11",
            handler="handler.rotate_cert",
            execution_role_arn="arn:aws:iam::123456789012:role/GarudaCertRotatorRole",
            memory_mb=512,
            timeout_seconds=60,
            is_vpc_connected=True,
            environment_variables={"KMS_KEY_ID": "arn:aws:kms:us-east-1:123456789012:key/k1"},
            tags={"Environment": "production", "Owner": "SecOps"},
        )
        fn2 = ServerlessFunction(
            function_id="FN-ALERT-FORWARDER",
            name="garuda-cloud-alert-forwarder",
            runtime="nodejs20.x",
            handler="index.handler",
            execution_role_arn="arn:aws:iam::123456789012:role/GarudaAdminBroadRole",  # Overprivileged test
            memory_mb=128,
            timeout_seconds=10,
            is_vpc_connected=False,
            tags={"Environment": "staging", "Owner": "Infra"},
        )
        self.register(fn1)
        self.register(fn2)

    def register(self, function: ServerlessFunction) -> None:
        self._functions[function.function_id] = function

    def get(self, function_id: str) -> Optional[ServerlessFunction]:
        return self._functions.get(function_id)

    def list_all(self) -> List[ServerlessFunction]:
        return list(self._functions.values())
