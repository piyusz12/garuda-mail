"""Garuda Distributed Sovereign AI Fabric - Inter-Node Communication & Segmentation.
Phase 34 Sections 34.14 & 34.15:
Cryptographically signed envelopes, mutual authentication, replay protection,
and logical network zone segmentation enforcement.
"""
from typing import Dict, List, Optional, Any
import time
import hashlib
import hmac
import uuid
import json

import os

from fabric.models import (
    SecureInterNodeEnvelope,
    NetworkZone,
)


class SecureInterNodeBus:
    """Manages encrypted/authenticated messaging and logical network isolation across nodes."""

    def __init__(self, shared_secret: Optional[str] = None):
        secret = shared_secret or os.environ.get("GARUDA_INTER_NODE_SECRET", "garuda-inter-node-shared-key-2026")
        self.shared_secret = secret.encode()
        self._processed_envelopes: Dict[str, float] = {}

    def create_envelope(
        self,
        request_id: str,
        source_node_id: str,
        target_node_id: str,
        network_zone: NetworkZone,
        job_id: str,
        payload: Dict[str, Any],
    ) -> SecureInterNodeEnvelope:
        """Constructs and signs a secure inter-node transmission envelope."""
        envelope_id = f"ENV-{uuid.uuid4().hex[:12].upper()}"
        now = time.time()

        # Build signature string
        sig_body = f"{envelope_id}:{request_id}:{source_node_id}:{target_node_id}:{network_zone.value}:{job_id}:{now}:{json.dumps(payload, sort_keys=True)}"
        signature = hmac.new(self.shared_secret, sig_body.encode(), hashlib.sha256).hexdigest()

        return SecureInterNodeEnvelope(
            envelope_id=envelope_id,
            request_id=request_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            network_zone=network_zone,
            job_id=job_id,
            payload=payload,
            timestamp=now,
            signature=signature,
            auth_context={"algorithm": "HMAC-SHA256", "control_plane_approved": True},
        )

    def verify_envelope(self, envelope: SecureInterNodeEnvelope, max_drift_sec: float = 60.0) -> tuple[bool, str]:
        """Validates signature integrity, prevents replay attacks, and checks message freshness."""
        now = time.time()

        # 1. Check timestamp freshness
        if abs(now - envelope.timestamp) > max_drift_sec:
            return False, f"Envelope expired or clock drift exceeded ({abs(now - envelope.timestamp):.1f}s > {max_drift_sec}s)"

        # 2. Check replay attack
        if envelope.envelope_id in self._processed_envelopes:
            return False, f"Replay attack detected: envelope '{envelope.envelope_id}' already processed"

        # 3. Verify signature
        sig_body = f"{envelope.envelope_id}:{envelope.request_id}:{envelope.source_node_id}:{envelope.target_node_id}:{envelope.network_zone.value}:{envelope.job_id}:{envelope.timestamp}:{json.dumps(envelope.payload, sort_keys=True)}"
        expected_sig = hmac.new(self.shared_secret, sig_body.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(envelope.signature, expected_sig):
            return False, "Invalid cryptographic HMAC signature"

        # Prune expired replay records
        cutoff = now - (max_drift_sec * 2)
        if len(self._processed_envelopes) > 100:
            self._processed_envelopes = {
                eid: ts for eid, ts in self._processed_envelopes.items() if ts > cutoff
            }

        self._processed_envelopes[envelope.envelope_id] = now
        return True, "Valid envelope"

    def validate_network_segmentation(
        self,
        source_zone: NetworkZone,
        target_zone: NetworkZone,
    ) -> tuple[bool, str]:
        """Enforces Section 34.15 Network Segmentation rules."""
        # Management network can orchestrate all zones
        if source_zone == NetworkZone.MANAGEMENT_NET or target_zone == NetworkZone.MANAGEMENT_NET:
            return True, "Management plane access permitted"

        # Same-zone traffic always allowed
        if source_zone == target_zone:
            return True, "Intra-zone traffic permitted"

        # Restricted AI can only communicate with Storage for authenticated DB, never General
        if source_zone == NetworkZone.RESTRICTED_AI and target_zone == NetworkZone.GENERAL_AI:
            return False, "Cross-zone violation: Direct communication from RESTRICTED_AI to GENERAL_AI blocked"
        if source_zone == NetworkZone.GENERAL_AI and target_zone == NetworkZone.RESTRICTED_AI:
            return False, "Cross-zone violation: Ingress from GENERAL_AI to RESTRICTED_AI blocked"

        # Storage network cannot be accessed directly by general workloads
        if target_zone == NetworkZone.STORAGE_NET and source_zone == NetworkZone.GENERAL_AI:
            return False, "Storage network is isolated from general network zone"

        return True, "Segment traversal authorized"
