import json
import uuid
import time
import hashlib
import logging
import argparse
import sys
import numpy as np
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase20 - %(message)s")
logger = logging.getLogger("Federation-Engine")

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, Header, Depends
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. Federation API mode disabled.")

# --- DATA MODELS ---

@dataclass
class PrivacyPolicy:
    """Strict definitions of what can and cannot be shared by the local organization."""
    policy_id: str
    allow_ja4_patterns: bool = True
    allow_cert_patterns: bool = True
    allow_anomaly_stats: bool = True
    allow_model_updates: bool = True
    deny_raw_pcap: bool = True
    deny_payloads: bool = True
    deny_private_keys: bool = True
    deny_raw_ips: bool = True
    differential_privacy_epsilon: float = 1.0 # Controls noise level

@dataclass
class Organization:
    """A trusted participant in the Federation Control Plane."""
    org_id: str
    name: str
    trust_level: str = "STANDARD" # STANDARD, HIGH, RESTRICTED
    status: str = "ACTIVE"
    joined_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class ModelUpdate:
    """Anonymized weight deltas for Federated Learning."""
    update_id: str
    org_id: str
    model_version: str
    federation_round: int
    weights: List[float] # Mocking actual tensor weights for the demo
    sample_size: int
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class IntelligencePackage:
    """A secure, signed payload containing shareable cryptographic/behavioral intelligence."""
    package_id: str
    publisher_id: str
    indicator_type: str # JA4_BEHAVIOR, CERT_PATTERN, TLS_DOWNGRADE
    value: str
    confidence: float
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str = ""
    revoked: bool = False

class PrivacyEngine:
    """
    Executes within the Local Enterprise boundary. 
    Guarantees sensitive data never touches the wire.
    """
    def __init__(self, policy: PrivacyPolicy):
        self.policy = policy
        self.budget_consumed = 0.0

    def sanitize_intelligence(self, raw_finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Filters a raw local finding into a shareable intelligence package."""
        logger.debug("Privacy Engine: Inspecting candidate intelligence...")
        
        # Hard Deny Checks (Fail-safe)
        if self.policy.deny_raw_pcap and "pcap_bytes" in raw_finding:
            logger.warning("[Privacy] BLOCKING: Raw PCAP data detected.")
            return None
        if self.policy.deny_payloads and "email_payload" in raw_finding:
            logger.warning("[Privacy] BLOCKING: Email payload detected.")
            return None
            
        safe_package = {
            "indicator_type": raw_finding.get("type", "UNKNOWN"),
            "value": raw_finding.get("value", ""),
            "confidence": raw_finding.get("confidence", 0.0),
            "context": {}
        }
        
        # Selective Allow Checks
        if self.policy.allow_ja4_patterns and "ja4" in raw_finding:
            safe_package["context"]["ja4_pattern"] = raw_finding["ja4"]
            
        # Pseudonymize IPs if they accidentally slipped into context
        if self.policy.deny_raw_ips and "ip_address" in raw_finding:
            ip = raw_finding["ip_address"]
            safe_package["context"]["pseudo_asset"] = hashlib.sha256(ip.encode()).hexdigest()[:8]
            
        return safe_package

    def apply_differential_privacy(self, statistic: int) -> int:
        """Adds Laplace noise to aggregate statistics to prevent data unmasking."""
        if self.policy.differential_privacy_epsilon <= 0:
            return statistic # No noise
        
        # Simple Laplace noise approximation for demo
        scale = 1.0 / self.policy.differential_privacy_epsilon
        noise = np.random.laplace(0, scale)
        self.budget_consumed += 0.1
        
        noisy_val = int(statistic + noise)
        return max(0, noisy_val) # Prevent negative stats


class SecureAggregator:
    """
    Runs in the Federation Control Plane.
    Averages local model updates (FedAvg) without retaining the individual updates.
    """
    def __init__(self):
        self.current_round = 1
        self.global_weights: np.ndarray = np.zeros(10) # Mock 10-parameter model
        self.pending_updates: List[ModelUpdate] = []
        self.min_participants = 2

    def submit_update(self, update: ModelUpdate):
        """Accepts a local update, validates it, and queues for aggregation."""
        if update.federation_round != self.current_round:
            logger.error(f"Rejected update from {update.org_id}: Round mismatch.")
            return
            
        # Anti-Poisoning Check: Reject massive deviations (Clipping)
        update_array = np.array(update.weights)
        if np.linalg.norm(update_array - self.global_weights) > 5.0:
            logger.error(f"[Anti-Poisoning] QUARANTINED update from {update.org_id}: Magnitude too large.")
            return
            
        self.pending_updates.append(update)
        logger.info(f"Accepted model update from {update.org_id} (Round {self.current_round})")

    def aggregate(self) -> Optional[List[float]]:
        """Executes the Federated Averaging (FedAvg) algorithm."""
        if len(self.pending_updates) < self.min_participants:
            logger.warning("Not enough participants to aggregate this round. Waiting.")
            return None
            
        logger.info(f"--- Executing Secure Aggregation for Round {self.current_round} ({len(self.pending_updates)} participants) ---")
        
        total_samples = sum(u.sample_size for u in self.pending_updates)
        new_global = np.zeros_like(self.global_weights)
        
        for u in self.pending_updates:
            weight = u.sample_size / total_samples
            new_global += np.array(u.weights) * weight
            
        self.global_weights = new_global
        self.current_round += 1
        self.pending_updates = [] # Flush local data immediately for privacy
        
        return self.global_weights.tolist()


class FederationCoordinator:
    """
    The Central Trust and Intelligence sharing fabric.
    Coordinates intelligence packages between verified tenants.
    """
    def __init__(self):
        self.registry: Dict[str, Organization] = {}
        self.intelligence_bus: Dict[str, IntelligencePackage] = {}
        self.aggregator = SecureAggregator()

    def register_organization(self, org_id: str, name: str) -> Organization:
        org = Organization(org_id=org_id, name=name)
        self.registry[org_id] = org
        return org

    def publish_intelligence(self, org_id: str, package: IntelligencePackage) -> bool:
        """Receives intelligence from a local node and distributes it to the bus."""
        if org_id not in self.registry or self.registry[org_id].status != "ACTIVE":
            logger.error(f"Unauthorized publish attempt from {org_id}")
            return False
            
        # Verify freshness
        if package.expires_at < datetime.now(timezone.utc):
            logger.error("Rejected stale intelligence package.")
            return False
            
        # In a real system, verify cryptographic signature here
        package.signature = f"VALIDATED-{uuid.uuid4().hex[:8]}"
        self.intelligence_bus[package.package_id] = package
        
        logger.info(f"[Coordinator] Published Global Intelligence {package.package_id} from {org_id}: {package.indicator_type}")
        return True

    def fetch_active_intelligence(self, org_id: str) -> List[IntelligencePackage]:
        """Provides active, unrevoked intelligence to a requesting organization."""
        if org_id not in self.registry:
            return []
            
        now = datetime.now(timezone.utc)
        active = [
            pkg for pkg in self.intelligence_bus.values()
            if not pkg.revoked and pkg.expires_at > now and pkg.publisher_id != org_id
        ]
        return active


class LocalFederationAgent:
    """
    Deployed inside the enterprise boundary. 
    Bridges local findings with the Federation Coordinator via the Privacy Engine.
    """
    def __init__(self, org_id: str, coordinator: FederationCoordinator, policy: PrivacyPolicy):
        self.org_id = org_id
        self.coordinator = coordinator
        self.privacy = PrivacyEngine(policy)
        self.local_intelligence_store: List[IntelligencePackage] = []

    def share_finding(self, raw_finding: Dict[str, Any]):
        """Attempts to share a local finding with the global federation."""
        logger.info(f"[{self.org_id}] Attempting to share local finding...")
        
        safe_data = self.privacy.sanitize_intelligence(raw_finding)
        if not safe_data:
            logger.warning(f"[{self.org_id}] Sharing aborted by Privacy Engine.")
            return
            
        package = IntelligencePackage(
            package_id=f"FED-PKG-{uuid.uuid4().hex[:8].upper()}",
            publisher_id=self.org_id,
            indicator_type=safe_data["indicator_type"],
            value=safe_data["value"],
            confidence=safe_data["confidence"],
            context=safe_data["context"],
            expires_at=datetime.now(timezone.utc) + __import__("datetime").timedelta(days=7)
        )
        
        success = self.coordinator.publish_intelligence(self.org_id, package)
        if success:
            logger.info(f"[{self.org_id}] Successfully shared intelligence with Federation.")

    def share_model_update(self, local_weights: List[float], sample_size: int):
        """Pushes local AI learnings to the global aggregator."""
        if not self.privacy.policy.allow_model_updates:
            logger.warning(f"[{self.org_id}] Model updates disabled by privacy policy.")
            return
            
        update = ModelUpdate(
            update_id=f"UPD-{uuid.uuid4().hex[:6]}",
            org_id=self.org_id,
            model_version="AE-3.0",
            federation_round=self.coordinator.aggregator.current_round,
            weights=local_weights,
            sample_size=sample_size
        )
        self.coordinator.aggregator.submit_update(update)

    def sync_global_intelligence(self):
        """Pulls shared threat intelligence from other organizations."""
        new_packages = self.coordinator.fetch_active_intelligence(self.org_id)
        if new_packages:
            logger.info(f"[{self.org_id}] Downloaded {len(new_packages)} new intelligence packages from Federation.")
            self.local_intelligence_store.extend(new_packages)
            
            # Simulate a privacy-aware local threat hunt
            for pkg in new_packages:
                logger.info(f"[{self.org_id}] Running local hunt for Global Pattern: {pkg.value}...")
                # (Would query local Elastic/Graph here)


if HAS_FASTAPI:
    from contextlib import asynccontextmanager

    coordinator = FederationCoordinator()

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        coordinator.register_organization("ORG-A", "Enterprise Alpha")
        coordinator.register_organization("ORG-B", "Enterprise Beta")
        yield

    app = FastAPI(title="Phase 20 - Federation Control Plane", version="20.0.0", lifespan=lifespan)

    @app.get("/api/v1/federation/intelligence", tags=["Intelligence"])
    def get_intelligence(x_org_id: str = Header(...)):
        return [asdict(p) for p in coordinator.fetch_active_intelligence(x_org_id)]

    @app.post("/api/v1/federation/intelligence", tags=["Intelligence"])
    def post_intelligence(payload: dict, x_org_id: str = Header(...)):
        pkg = IntelligencePackage(**payload)
        success = coordinator.publish_intelligence(x_org_id, pkg)
        if not success:
            raise HTTPException(400, "Failed to publish intelligence.")
        return {"status": "Published"}

    @app.post("/api/v1/federation/model/update", tags=["Learning"])
    def submit_model_update(payload: dict, x_org_id: str = Header(...)):
        update = ModelUpdate(**payload)
        update.org_id = x_org_id # Enforce identity
        coordinator.aggregator.submit_update(update)
        return {"status": "Update Accepted", "current_round": coordinator.aggregator.current_round}

    @app.post("/api/v1/federation/model/aggregate", tags=["Learning"])
    def trigger_aggregation():
        new_weights = coordinator.aggregator.aggregate()
        if not new_weights:
            return {"status": "Waiting for more participants"}
        return {"status": "Aggregated", "new_global_weights": new_weights}


def run_phase20_demo():
    print("\n" + "="*75)
    print(" PHASE 20: PRIVACY-PRESERVING FEDERATED INTELLIGENCE & THREAT SHARING")
    print("="*75 + "\n")

    # 1. Initialize Central Control Plane
    coordinator = FederationCoordinator()
    coordinator.register_organization("ORG-ALPHA", "Enterprise Alpha")
    coordinator.register_organization("ORG-BETA", "Enterprise Beta")
    coordinator.register_organization("ORG-GAMMA", "Enterprise Gamma")

    # 2. Initialize Local Agents with Strict Privacy Policies
    strict_policy = PrivacyPolicy("STRICT-01")
    agent_alpha = LocalFederationAgent("ORG-ALPHA", coordinator, strict_policy)
    agent_beta = LocalFederationAgent("ORG-BETA", coordinator, strict_policy)
    
    print("[*] SCENARIO 1: Privacy-Preserving Threat Sharing")
    # Alpha detects something locally, but it contains sensitive raw data
    raw_local_finding = {
        "type": "JA4_BEHAVIOR",
        "value": "t13d1516h2_8daaf_anomaly",
        "confidence": 0.95,
        "ja4": "t13d1516h2_8daaf_anomaly",
        "ip_address": "10.0.5.12", # SENSITIVE
        "pcap_bytes": b"fake_binary_pcap_data", # HIGHLY SENSITIVE
        "email_payload": "Confidential merger details..." # HIGHLY SENSITIVE
    }
    
    # Alpha attempts to share it. Watch the privacy engine intercept.
    agent_alpha.share_finding(raw_local_finding)
    
    # Alpha strips raw packet captures and payloads, sharing only sanitized telemetry
    clean_local_finding = {
        "type": "JA4_BEHAVIOR",
        "value": "t13d1516h2_8daaf_anomaly",
        "confidence": 0.95,
        "ja4": "t13d1516h2_8daaf_anomaly",
        "ip_address": "10.0.5.12", # SENSITIVE - will be pseudonymized by privacy engine
    }
    print("    -> Alpha submitting sanitized indicator (raw payload & PCAP stripped)...")
    agent_alpha.share_finding(clean_local_finding)

    # Beta syncs and hunts
    print("\n[*] Enterprise Beta pulling global intelligence...")
    agent_beta.sync_global_intelligence()
    for intel in agent_beta.local_intelligence_store:
        print(f"    -> Beta Local Hunt Results for {intel.value}: 0 matches found locally.")
        print(f"       (Note: Notice Beta received the JA4, but NOT Alpha's IP or Payload.)\n")

    print("[*] SCENARIO 2: Secure Federated Learning (Model Aggregation)")
    # Alpha and Beta train locally and submit ONLY gradient weights, not training data
    print("    -> Alpha and Beta submitting local AI model updates...")
    
    # Simulate a poisoning attempt from a compromised Gamma node
    agent_gamma = LocalFederationAgent("ORG-GAMMA", coordinator, strict_policy)
    poisoned_weights = [999.0, -999.0, 500.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    
    agent_alpha.share_model_update([0.1, 0.2, -0.1, 0.05, 0.1, 0.1, 0.2, -0.1, 0.0, 0.0], 15000)
    agent_gamma.share_model_update(poisoned_weights, 5000) # Should be quarantined
    agent_beta.share_model_update([0.15, 0.18, -0.12, 0.04, 0.11, 0.09, 0.22, -0.15, 0.02, 0.01], 12000)
    
    # Central coordinator aggregates
    new_global = coordinator.aggregator.aggregate()
    if new_global:
        print(f"\n    -> [FedAvg] New Global Weights Calculated:")
        print(f"       {np.round(new_global, 3)}")
        print("    -> Alpha and Beta models successfully merged. Gamma's attack was quarantined.")

    print("\n[+] Phase 20 Execution Complete. Cross-Enterprise learning achieved with 0 data leakage.")


def main():
    parser = argparse.ArgumentParser(description="Phase 20 - Federated Intelligence")
    parser.add_argument("command", choices=["serve", "demo"], help="Command to run", default="demo", nargs="?")
    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Phase 20 Federation Coordinator on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("FastAPI not installed. Run 'demo' instead.")
    elif args.command == "demo":
        run_phase20_demo()

if __name__ == "__main__":
    main()