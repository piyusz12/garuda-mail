"""
Multi-Cloud Normalization Engine.
Component 4: Maps heterogeneous provider payloads (AWS, Azure, GCP, On-Prem) into canonical CloudResource representations.
"""
from typing import Dict, List, Optional, Any
import uuid

from cloud.inventory.accounts import CloudProvider, EnvironmentType
from cloud.inventory.resources import CloudResource, CloudResourceType
from identity.ingestion.services import ResourceClassification


class MultiCloudNormalizer:
    """Normalizes heterogeneous cloud resource descriptors into standardized CloudResource entities."""

    @classmethod
    def normalize_aws_resource(cls, *args, **kwargs) -> CloudResource:
        if len(args) >= 3 and isinstance(args[0], str) and isinstance(args[1], dict):
            r_type_arg, raw, account_id = args[0], args[1], args[2]
            raw["ResourceType"] = r_type_arg
            environment = args[3] if len(args) > 3 else kwargs.get("environment", EnvironmentType.PRODUCTION)
        elif len(args) >= 2:
            raw, account_id = args[0], args[1]
            environment = args[2] if len(args) > 2 else kwargs.get("environment", EnvironmentType.PRODUCTION)
        else:
            raw = kwargs.get("raw", {})
            account_id = kwargs.get("account_id", "")
            environment = kwargs.get("environment", EnvironmentType.PRODUCTION)

        res_type = CloudResourceType.VIRTUAL_MACHINE
        r_type_raw = str(raw.get("ResourceType", "")).upper()
        if "EKS" in r_type_raw or "CLUSTER" in r_type_raw:
            res_type = CloudResourceType.KUBERNETES_CLUSTER
        elif "S3" in r_type_raw or "BUCKET" in r_type_raw:
            res_type = CloudResourceType.STORAGE_BUCKET
        elif "RDS" in r_type_raw or "AURORA" in r_type_raw or "SQL" in r_type_raw:
            res_type = CloudResourceType.DATABASE
        elif "ELB" in r_type_raw or "LOADBALANCER" in r_type_raw:
            res_type = CloudResourceType.LOAD_BALANCER
        elif "APIGATEWAY" in r_type_raw:
            res_type = CloudResourceType.API_GATEWAY
        elif "LAMBDA" in r_type_raw or "FUNCTION" in r_type_raw:
            res_type = CloudResourceType.SERVERLESS_FUNCTION

        is_public = raw.get("IsPublic", False)
        if "PublicAccessBlock" in raw:
            is_public = not raw["PublicAccessBlock"]

        return CloudResource(
            resource_id=raw.get("ResourceId", f"AWS-{uuid.uuid4().hex[:6].upper()}"),
            name=raw.get("ResourceName", raw.get("Name", "unnamed-aws-resource")),
            resource_type=res_type,
            provider=CloudProvider.AWS,
            account_id=account_id,
            region=raw.get("Region", "us-east-1"),
            environment=environment,
            classification=ResourceClassification(raw.get("Classification", "INTERNAL")),
            is_internet_facing=is_public,
            encryption_enabled=raw.get("Encrypted", True),
            logging_enabled=raw.get("LoggingEnabled", True),
            tags=raw.get("Tags", {}),
            attributes=raw.get("Attributes", {}),
        )

    @classmethod
    def normalize_gcp_resource(cls, *args, **kwargs) -> CloudResource:
        if len(args) >= 3 and isinstance(args[0], str) and isinstance(args[1], dict):
            r_type_arg, raw, account_id = args[0], args[1], args[2]
            raw["kind"] = r_type_arg
            environment = args[3] if len(args) > 3 else kwargs.get("environment", EnvironmentType.PRODUCTION)
        elif len(args) >= 2:
            raw, account_id = args[0], args[1]
            environment = args[2] if len(args) > 2 else kwargs.get("environment", EnvironmentType.PRODUCTION)
        else:
            raw = kwargs.get("raw", {})
            account_id = kwargs.get("account_id", "")
            environment = kwargs.get("environment", EnvironmentType.PRODUCTION)

        res_type = CloudResourceType.VIRTUAL_MACHINE
        kind = str(raw.get("kind", "")).lower()
        if "gke" in kind or "cluster" in kind:
            res_type = CloudResourceType.KUBERNETES_CLUSTER
        elif "storage" in kind or "bucket" in kind:
            res_type = CloudResourceType.STORAGE_BUCKET
        elif "sql" in kind or "database" in kind:
            res_type = CloudResourceType.DATABASE
        elif "function" in kind:
            res_type = CloudResourceType.SERVERLESS_FUNCTION

        return CloudResource(
            resource_id=raw.get("id", f"GCP-{uuid.uuid4().hex[:6].upper()}"),
            name=raw.get("name", "unnamed-gcp-resource"),
            resource_type=res_type,
            provider=CloudProvider.GCP,
            account_id=account_id,
            region=raw.get("location", "us-central1"),
            environment=environment,
            classification=ResourceClassification(raw.get("classification", "INTERNAL")),
            is_internet_facing=raw.get("publicExposure", False),
            encryption_enabled=raw.get("kmsKeyProtected", True),
            logging_enabled=raw.get("auditLogging", True),
            tags=raw.get("labels", {}),
            attributes=raw.get("properties", {}),
        )

        return CloudResource(
            resource_id=raw.get("id", f"GCP-{uuid.uuid4().hex[:6].upper()}"),
            name=raw.get("name", "unnamed-gcp-resource"),
            resource_type=res_type,
            provider=CloudProvider.GCP,
            account_id=account_id,
            region=raw.get("location", "us-central1"),
            environment=environment,
            classification=ResourceClassification(raw.get("classification", "INTERNAL")),
            is_internet_facing=raw.get("publicExposure", False),
            encryption_enabled=raw.get("kmsKeyProtected", True),
            logging_enabled=raw.get("auditLogging", True),
            tags=raw.get("labels", {}),
            attributes=raw.get("properties", {}),
        )

    @staticmethod
    def normalize_azure_resource(raw: Dict[str, Any], account_id: str, environment: EnvironmentType = EnvironmentType.PRODUCTION) -> CloudResource:
        res_type = CloudResourceType.VIRTUAL_MACHINE
        t_type = raw.get("type", "").lower()
        if "managedclusters" in t_type or "aks" in t_type:
            res_type = CloudResourceType.KUBERNETES_CLUSTER
        elif "storageaccounts" in t_type or "blob" in t_type:
            res_type = CloudResourceType.STORAGE_BUCKET
        elif "sql" in t_type:
            res_type = CloudResourceType.DATABASE

        return CloudResource(
            resource_id=raw.get("id", f"AZURE-{uuid.uuid4().hex[:6].upper()}"),
            name=raw.get("name", "unnamed-azure-resource"),
            resource_type=res_type,
            provider=CloudProvider.AZURE,
            account_id=account_id,
            region=raw.get("location", "eastus"),
            environment=environment,
            classification=ResourceClassification(raw.get("classification", "INTERNAL")),
            is_internet_facing=raw.get("publicNetworkAccess", False),
            encryption_enabled=raw.get("encryption", True),
            logging_enabled=raw.get("diagnosticsEnabled", True),
            tags=raw.get("tags", {}),
            attributes=raw.get("properties", {}),
        )
