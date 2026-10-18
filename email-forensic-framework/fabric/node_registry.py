"""Garuda Distributed Sovereign AI Fabric - Node Registry & Enrollment.
Phase 34 Sections 34.2, 34.3, 34.4, 34.6, 34.21:
Node registry, cryptographic identity, secure enrollment approval workflow,
and capability discovery.
"""
from typing import Dict, List, Optional, Any
import hashlib
import hmac
import time
import uuid
import os

from fabric.models import (
    FabricNodeRecord,
    NodeIdentity,
    EnrollmentRequest,
    EnrollmentStatus,
    NodeStatus,
    NodeTrust,
    NodeRole,
    NetworkZone,
    ModelLifecycleStatus,
)


class NodeRegistry:
    """Central control-plane registry for fabric nodes and secure enrollment."""

    def __init__(self, cluster_secret: Optional[str] = None):
        self.cluster_secret = cluster_secret or os.environ.get("GARUDA_FABRIC_SECRET", "garuda-control-plane-fabric-secret-2026")
        self._nodes: Dict[str, FabricNodeRecord] = {}
        self._identities: Dict[str, NodeIdentity] = {}
        self._enrollment_requests: Dict[str, EnrollmentRequest] = {}
        self.seed_default_nodes()

    @property
    def nodes(self) -> Dict[str, FabricNodeRecord]:
        return self._nodes

    def generate_node_identity(self, node_id: str) -> NodeIdentity:
        """Issues cryptographic identity credentials and fingerprint for a node."""
        seed = f"{node_id}:{self.cluster_secret}:{time.time()}"
        pub_key = f"GARUDA-PUBKEY-{hashlib.sha256(seed.encode()).hexdigest()[:32]}"
        priv_hash = hashlib.sha256(f"PRIV:{seed}".encode()).hexdigest()
        fingerprint = f"SHA256:{hashlib.sha256(pub_key.encode()).hexdigest()[:24].upper()}"
        cert_pem = (
            f"-----BEGIN GARUDA NODE CERTIFICATE-----\n"
            f"NODE_ID: {node_id}\n"
            f"FINGERPRINT: {fingerprint}\n"
            f"PUBLIC_KEY: {pub_key}\n"
            f"ISSUER: GARUDA-CONTROL-PLANE-CA\n"
            f"VALID_UNTIL: {time.time() + (365 * 86400)}\n"
            f"-----END GARUDA NODE CERTIFICATE-----"
        )
        identity = NodeIdentity(
            node_id=node_id,
            public_key=pub_key,
            private_key_hash=priv_hash,
            certificate_pem=cert_pem,
            fingerprint=fingerprint,
        )
        self._identities[node_id] = identity
        return identity

    def verify_node_identity(self, node_id: str, public_key: str) -> bool:
        """Verifies if the advertised public key matches the issued identity."""
        identity = self._identities.get(node_id)
        if not identity:
            return False
        if not identity.is_valid():
            return False
        return identity.public_key == public_key

    def seed_default_nodes(self):
        """Seeds standard flagship nodes matching SIH physical and VM architecture."""
        # Node 1: Workstation RTX 4060 Laptop (Compact LLM, coding, RAG, embeddings)
        node1_id = "NODE-001"
        self.generate_node_identity(node1_id)
        self._nodes[node1_id] = FabricNodeRecord(
            node_id=node1_id,
            hostname="garuda-rtx4060-workstation",
            ip_address="192.168.1.101",
            status=NodeStatus.HEALTHY,
            role=NodeRole.WORKER_GPU,
            trust_level=NodeTrust.TRUSTED,
            network_zone=NetworkZone.RESTRICTED_AI,
            cpu_cores=16,
            cpu_usage_pct=24.5,
            ram_total_gb=16.0,
            ram_used_gb=7.8,
            gpu_name="NVIDIA GeForce RTX 4060 Laptop GPU",
            vram_total_gb=8.0,
            vram_used_gb=3.2,
            models_loaded={
                "qwen-local": ModelLifecycleStatus.READY,
                "local-approved": ModelLifecycleStatus.READY,
                "bge-embeddings": ModelLifecycleStatus.READY,
            },
            capabilities=["chat", "coding", "embeddings", "reranking", "llm_inference", "rag"],
            software_version="34.0.0",
            active_jobs=0,
            temperature_c=52.0,
            disk_used_pct=42.0,
        )

        # Node 2: High-VRAM AI Server GPU Cluster (Large models, Vision, Multi-Agent)
        node2_id = "NODE-002"
        self.generate_node_identity(node2_id)
        self._nodes[node2_id] = FabricNodeRecord(
            node_id=node2_id,
            hostname="garuda-ai-server-02",
            ip_address="192.168.1.102",
            status=NodeStatus.HEALTHY,
            role=NodeRole.WORKER_GPU,
            trust_level=NodeTrust.TRUSTED,
            network_zone=NetworkZone.INTERNAL_AI,
            cpu_cores=32,
            cpu_usage_pct=38.0,
            ram_total_gb=64.0,
            ram_used_gb=22.4,
            gpu_name="NVIDIA RTX 4090",
            vram_total_gb=24.0,
            vram_used_gb=8.5,
            models_loaded={
                "qwen-coder-7b": ModelLifecycleStatus.READY,
                "qwen-vl-vision": ModelLifecycleStatus.READY,
                "qwen-local": ModelLifecycleStatus.READY,
            },
            capabilities=["chat", "llm_inference", "vision", "coding", "embeddings", "image_processing", "video_analysis"],
            software_version="34.0.0",
            active_jobs=0,
            temperature_c=58.0,
            disk_used_pct=29.0,
        )

        # Node 3: Storage & CPU Worker (Vector Store, Document Ingestion, Batch Parsing)
        node3_id = "NODE-003"
        self.generate_node_identity(node3_id)
        self._nodes[node3_id] = FabricNodeRecord(
            node_id=node3_id,
            hostname="garuda-storage-worker",
            ip_address="192.168.1.103",
            status=NodeStatus.HEALTHY,
            role=NodeRole.STORAGE_RAG,
            trust_level=NodeTrust.TRUSTED,
            network_zone=NetworkZone.STORAGE_NET,
            cpu_cores=16,
            cpu_usage_pct=18.5,
            ram_total_gb=32.0,
            ram_used_gb=11.2,
            gpu_name="None (CPU Only)",
            vram_total_gb=0.0,
            vram_used_gb=0.0,
            models_loaded={
                "bge-embeddings": ModelLifecycleStatus.READY,
            },
            capabilities=["vector_store", "document_processing", "embeddings", "database"],
            software_version="34.0.0",
            active_jobs=0,
            temperature_c=41.0,
            disk_used_pct=48.0,
        )

        # Node 4: Quarantined node for security testing
        node4_id = "NODE-004-QUARANTINED"
        self.generate_node_identity(node4_id)
        self._nodes[node4_id] = FabricNodeRecord(
            node_id=node4_id,
            hostname="untrusted-rogue-node",
            ip_address="192.168.1.250",
            status=NodeStatus.QUARANTINED,
            role=NodeRole.WORKER_GPU,
            trust_level=NodeTrust.QUARANTINED,
            network_zone=NetworkZone.GENERAL_AI,
            cpu_cores=8,
            cpu_usage_pct=95.0,
            ram_total_gb=16.0,
            ram_used_gb=15.0,
            gpu_name="Generic GPU",
            vram_total_gb=8.0,
            vram_used_gb=8.0,
            models_loaded={},
            capabilities=["chat"],
            software_version="33.1.0",
            active_jobs=0,
            temperature_c=85.0,
            disk_used_pct=92.0,
            security_state="SUSPICIOUS_POLICY_VIOLATION",
        )

    # --------------------------------------------------------------------------
    # Enrollment Workflow (Section 34.4)
    # --------------------------------------------------------------------------

    def submit_enrollment_request(
        self,
        hostname: str,
        ip_address: str,
        role: NodeRole,
        advertised_gpu: str,
        advertised_vram_gb: float,
        advertised_ram_gb: float,
        advertised_capabilities: List[str],
        public_key: str,
        requested_zone: NetworkZone = NetworkZone.INTERNAL_AI,
    ) -> EnrollmentRequest:
        """New worker requests enrollment into the fabric."""
        req_id = f"ENROLL-{uuid.uuid4().hex[:8].upper()}"
        req = EnrollmentRequest(
            request_id=req_id,
            hostname=hostname,
            ip_address=ip_address,
            role=role,
            advertised_gpu=advertised_gpu,
            advertised_vram_gb=advertised_vram_gb,
            advertised_ram_gb=advertised_ram_gb,
            advertised_capabilities=advertised_capabilities,
            public_key=public_key,
            requested_zone=requested_zone,
        )
        self._enrollment_requests[req_id] = req
        return req

    def list_enrollment_requests(self, status: Optional[EnrollmentStatus] = None) -> List[EnrollmentRequest]:
        """Lists pending or historical enrollment requests for admin review."""
        reqs = list(self._enrollment_requests.values())
        if status:
            reqs = [r for r in reqs if r.status == status]
        return sorted(reqs, key=lambda r: r.requested_at, reverse=True)

    def approve_enrollment(
        self,
        request_id: str,
        admin_id: str = "admin@garuda.internal",
        trust_level: NodeTrust = NodeTrust.TRUSTED,
    ) -> FabricNodeRecord:
        """Administrator approves a pending node enrollment and issues fabric credentials."""
        req = self._enrollment_requests.get(request_id)
        if not req:
            raise ValueError(f"Enrollment request '{request_id}' not found")
        if req.status != EnrollmentStatus.PENDING_APPROVAL:
            raise ValueError(f"Request '{request_id}' is already {req.status.value}")

        assigned_id = f"GARUDA-NODE-{uuid.uuid4().hex[:5].upper()}"
        req.status = EnrollmentStatus.APPROVED
        req.decision_reason = f"Approved by administrator {admin_id}"
        req.assigned_node_id = assigned_id

        # Generate cryptographic identity
        self.generate_node_identity(assigned_id)

        # Register new node
        new_node = FabricNodeRecord(
            node_id=assigned_id,
            hostname=req.hostname,
            ip_address=req.ip_address,
            status=NodeStatus.HEALTHY,
            role=req.role,
            trust_level=trust_level,
            network_zone=req.requested_zone,
            cpu_cores=16,
            cpu_usage_pct=5.0,
            ram_total_gb=req.advertised_ram_gb,
            ram_used_gb=1.0,
            gpu_name=req.advertised_gpu,
            vram_total_gb=req.advertised_vram_gb,
            vram_used_gb=0.0,
            models_loaded={},
            capabilities=req.advertised_capabilities,
            software_version="34.0.0",
            active_jobs=0,
        )
        self._nodes[assigned_id] = new_node
        return new_node

    def reject_enrollment(
        self,
        request_id: str,
        reason: str,
        admin_id: str = "admin@garuda.internal",
    ) -> EnrollmentRequest:
        """Administrator rejects a pending node enrollment."""
        req = self._enrollment_requests.get(request_id)
        if not req:
            raise ValueError(f"Enrollment request '{request_id}' not found")
        req.status = EnrollmentStatus.REJECTED
        req.decision_reason = f"Rejected by {admin_id}: {reason}"
        return req

    # --------------------------------------------------------------------------
    # Node Management & Queries
    # --------------------------------------------------------------------------

    def get_node(self, node_id: str) -> Optional[FabricNodeRecord]:
        return self._nodes.get(node_id)

    def list_nodes(
        self,
        status: Optional[NodeStatus] = None,
        zone: Optional[NetworkZone] = None,
        capability: Optional[str] = None,
    ) -> List[FabricNodeRecord]:
        nodes = list(self._nodes.values())
        if status:
            nodes = [n for n in nodes if n.status == status]
        if zone:
            nodes = [n for n in nodes if n.network_zone == zone]
        if capability:
            nodes = [n for n in nodes if capability in n.capabilities]
        return sorted(nodes, key=lambda n: n.node_id)

    def quarantine_node(self, node_id: str, reason: str) -> FabricNodeRecord:
        """Immediately quarantines an anomalous or untrusted worker."""
        node = self._nodes.get(node_id)
        if not node:
            raise ValueError(f"Node '{node_id}' not found")
        node.status = NodeStatus.QUARANTINED
        node.trust_level = NodeTrust.QUARANTINED
        node.security_state = f"QUARANTINED: {reason}"
        return node

    def get_healthy_nodes(self) -> List[FabricNodeRecord]:
        """Returns list of nodes with HEALTHY status."""
        return self.list_nodes(status=NodeStatus.HEALTHY)

    def get_capabilities_matrix(self) -> Dict[str, List[str]]:
        """Capability discovery map across all registered nodes."""
        matrix: Dict[str, List[str]] = {}
        for node in self._nodes.values():
            if node.status in (NodeStatus.HEALTHY, NodeStatus.DEGRADED):
                for cap in node.capabilities:
                    matrix.setdefault(cap, []).append(node.node_id)
        return matrix
