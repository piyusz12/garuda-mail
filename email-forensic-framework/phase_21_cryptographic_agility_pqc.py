import json
import uuid
import time
import logging
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase21 - %(message)s")
logger = logging.getLogger("Crypto-Agility-Engine")

try:
    from fastapi import FastAPI, HTTPException
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. API mode disabled.")

# --- DATA MODELS: INVENTORY & PQC REGISTRY ---

@dataclass
class CryptoAlgorithm:
    """Represents a cryptographic algorithm and its lifecycle status."""
    algorithm_id: str
    family: str # RSA, ECC, MODULE_LATTICE, HASH
    purposes: List[str] # KEY_ESTABLISHMENT, SIGNATURE, ENCRYPTION
    status: str # APPROVED, DEPRECATED, LEGACY, TRANSITIONING
    is_quantum_safe: bool = False

@dataclass
class CryptoAsset:
    """A specific instance of cryptography observed in the enterprise."""
    crypto_asset_id: str
    asset_type: str # CERTIFICATE, ALGORITHM, PROTOCOL
    algorithm_id: str
    associated_assets: Set[str] = field(default_factory=set)
    client_dependencies: Set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_pcaps: List[str] = field(default_factory=list)

@dataclass
class PQCStandard:
    """Registry entry for NIST Post-Quantum Cryptography standards."""
    standard_id: str
    algorithm: str
    category: str # KEM, SIGNATURE
    status: str # FINAL, DRAFT
    source: str = "NIST"

# --- DATA MODELS: AGILITY, MIGRATION & VERIFICATION ---

@dataclass
class AgilityScorecard:
    asset_id: str
    algorithm_replaceability: str # HIGH, MEDIUM, LOW
    certificate_replaceability: str
    dependency_visibility: str
    inventory_completeness: float # 0.0 to 1.0
    overall_agility: str

@dataclass
class MigrationScenario:
    scenario_id: str
    target_asset: str
    current_crypto: str
    target_crypto: str
    status: str = "DRAFT" # DRAFT, SIMULATED, APPROVED, VERIFIED
    blockers: List[str] = field(default_factory=list)
    impacted_clients: List[str] = field(default_factory=list)

@dataclass
class VerificationResult:
    migration_id: str
    expected_state: Dict[str, Any]
    observed_state: Dict[str, Any]
    status: str # PASS, FAIL, PARTIAL
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_pcaps: List[str] = field(default_factory=list)


class CryptoInventoryManager:
    """Maintains the extended dynamic Cryptographic Bill of Materials (CBOM)."""
    
    def __init__(self):
        self.algorithms: Dict[str, CryptoAlgorithm] = self._load_algorithm_registry()
        self.pqc_standards: Dict[str, PQCStandard] = self._load_pqc_registry()
        self.crypto_assets: Dict[str, CryptoAsset] = {}

    def _load_algorithm_registry(self) -> Dict[str, CryptoAlgorithm]:
        return {
            "RSA-2048": CryptoAlgorithm("RSA-2048", "RSA", ["SIGNATURE", "KEY_ESTABLISHMENT"], "LEGACY", False),
            "ECDSA-P256": CryptoAlgorithm("ECDSA-P256", "ECC", ["SIGNATURE"], "APPROVED", False),
            "ML-KEM-768": CryptoAlgorithm("ML-KEM-768", "MODULE_LATTICE", ["KEY_ESTABLISHMENT"], "APPROVED", True),
            "ML-DSA-65": CryptoAlgorithm("ML-DSA-65", "MODULE_LATTICE", ["SIGNATURE"], "APPROVED", True)
        }

    def _load_pqc_registry(self) -> Dict[str, PQCStandard]:
        return {
            "FIPS-203": PQCStandard("FIPS-203", "ML-KEM", "KEM", "FINAL"),
            "FIPS-204": PQCStandard("FIPS-204", "ML-DSA", "SIGNATURE", "FINAL"),
            "FIPS-205": PQCStandard("FIPS-205", "SLH-DSA", "SIGNATURE", "FINAL")
        }

    def discover_asset(self, asset_type: str, algorithm_id: str, enterprise_asset: str, client_dep: str, pcap: str):
        """Processes forensic observations into the unified cryptographic graph."""
        # Create deterministic ID for the crypto instance
        crypto_id = f"CRYPTO-{algorithm_id}-{enterprise_asset}"
        
        if crypto_id not in self.crypto_assets:
            self.crypto_assets[crypto_id] = CryptoAsset(
                crypto_asset_id=crypto_id,
                asset_type=asset_type,
                algorithm_id=algorithm_id
            )
            
        asset = self.crypto_assets[crypto_id]
        asset.associated_assets.add(enterprise_asset)
        if client_dep:
            asset.client_dependencies.add(client_dep)
        if pcap not in asset.source_pcaps:
            asset.source_pcaps.append(pcap)
        asset.last_seen = datetime.now(timezone.utc)


class CryptoAgilityAssessor:
    """Evaluates how easily an asset's cryptography can be migrated."""
    
    def assess(self, enterprise_asset: str, inventory: CryptoInventoryManager) -> AgilityScorecard:
        logger.info(f"Assessing Cryptographic Agility for {enterprise_asset}...")
        
        # Find all crypto tied to this asset
        related_crypto = [c for c in inventory.crypto_assets.values() if enterprise_asset in c.associated_assets]
        
        # Heuristics for demo
        dep_count = sum(len(c.client_dependencies) for c in related_crypto)
        
        visibility = "HIGH" if dep_count > 0 else "LOW"
        replaceability = "MEDIUM" if dep_count > 5 else "HIGH" # Harder to replace if many clients depend on it
        
        return AgilityScorecard(
            asset_id=enterprise_asset,
            algorithm_replaceability=replaceability,
            certificate_replaceability="HIGH",
            dependency_visibility=visibility,
            inventory_completeness=0.95,
            overall_agility="HIGH" if replaceability == "HIGH" else "MEDIUM"
        )


class PQCReadinessEngine:
    """Determines exposure to Harvest-Now-Decrypt-Later (HNDL) and migration status."""
    
    def assess_asset(self, enterprise_asset: str, inventory: CryptoInventoryManager) -> Dict[str, Any]:
        related_crypto = [c for c in inventory.crypto_assets.values() if enterprise_asset in c.associated_assets]
        
        vulnerable_algorithms = []
        pqc_algorithms = []
        
        for c in related_crypto:
            alg = inventory.algorithms.get(c.algorithm_id)
            if not alg:
                continue
            if not alg.is_quantum_safe and "KEY_ESTABLISHMENT" in alg.purposes:
                vulnerable_algorithms.append(alg.algorithm_id)
            elif alg.is_quantum_safe:
                pqc_algorithms.append(alg.algorithm_id)
                
        status = "QUANTUM_SECURE" if pqc_algorithms and not vulnerable_algorithms else "QUANTUM_VULNERABLE"
        if pqc_algorithms and vulnerable_algorithms:
            status = "HYBRID_TRANSITIONING"
            
        return {
            "asset_id": enterprise_asset,
            "pqc_status": status,
            "hndl_exposure": len(vulnerable_algorithms) > 0,
            "vulnerable_crypto": vulnerable_algorithms,
            "quantum_safe_crypto": pqc_algorithms,
            "migration_state": "MIGRATION_CANDIDATE" if status == "QUANTUM_VULNERABLE" else "DEPLOYED"
        }

class MigrationSimulator:
    """Connects to Phase 16 Digital Twin to simulate compatibility breakage."""
    
    def simulate(self, target_asset: str, target_crypto: str, inventory: CryptoInventoryManager) -> MigrationScenario:
        logger.info(f"Simulating Migration: {target_asset} -> {target_crypto}")
        
        scenario = MigrationScenario(
            scenario_id=f"MIG-SCN-{uuid.uuid4().hex[:6].upper()}",
            target_asset=target_asset,
            current_crypto="RSA-2048", # Mocked current state
            target_crypto=target_crypto
        )
        
        # 1. Identify current dependencies
        related_crypto = [c for c in inventory.crypto_assets.values() if target_asset in c.associated_assets]
        all_clients = set()
        for c in related_crypto:
            all_clients.update(c.client_dependencies)
            
        # 2. Simulate Compatibility (Mock Logic)
        for client in all_clients:
            if "Legacy" in client:
                scenario.blockers.append(f"Incompatible Client: {client} does not support {target_crypto}")
                scenario.impacted_clients.append(client)
            elif "Unknown" in client:
                scenario.blockers.append(f"Unknown Dependency: {client} capabilities unverified.")
                scenario.impacted_clients.append(client)
                
        scenario.status = "SIMULATED"
        return scenario


class MigrationVerificationEngine:
    """Phase 21 Verification: Compares Expected Target State vs Observed Live State."""
    
    def verify(self, migration_id: str, expected_crypto: str, newly_observed_crypto: List[str], pcap_evidence: str) -> VerificationResult:
        logger.info(f"Verifying Migration {migration_id} using {pcap_evidence}...")
        
        # 1. Check if the target cryptography is now present
        target_found = expected_crypto in newly_observed_crypto
        
        # 2. Check if the old cryptography is GONE (No rollback/fallback happening)
        legacy_found = "RSA-2048" in newly_observed_crypto
        
        if target_found and not legacy_found:
            status = "PASS"
        elif target_found and legacy_found:
            status = "PARTIAL (Hybrid/Fallback observed)"
        else:
            status = "FAIL (Target crypto not observed)"
            
        result = VerificationResult(
            migration_id=migration_id,
            expected_state={"crypto": expected_crypto, "legacy_disabled": True},
            observed_state={"active_crypto": newly_observed_crypto},
            status=status,
            evidence_pcaps=[pcap_evidence]
        )
        
        logger.info(f"Verification Result: {status}")
        return result

if HAS_FASTAPI:
    app = FastAPI(title="Phase 21 - Cryptographic Agility & Migration", version="21.0.0")
    
    inventory = CryptoInventoryManager()
    agility_assessor = CryptoAgilityAssessor()
    pqc_engine = PQCReadinessEngine()
    simulator = MigrationSimulator()
    verifier = MigrationVerificationEngine()
    
    @app.get("/api/v1/pqc/standards", tags=["PQC Registry"])
    def get_pqc_standards():
        return {k: asdict(v) for k, v in inventory.pqc_standards.items()}

    @app.get("/api/v1/crypto/agility/{asset_id}", tags=["Agility"])
    def get_agility_score(asset_id: str):
        return asdict(agility_assessor.assess(asset_id, inventory))

    @app.post("/api/v1/migrations/simulate", tags=["Migration"])
    def simulate_migration(target_asset: str, target_crypto: str):
        scenario = simulator.simulate(target_asset, target_crypto, inventory)
        return asdict(scenario)


def run_phase21_demo():
    print("\n" + "="*75)
    print(" PHASE 21: CRYPTOGRAPHIC AGILITY & POST-QUANTUM MIGRATION PLATFORM")
    print("="*75 + "\n")
    
    inv = CryptoInventoryManager()
    agility = CryptoAgilityAssessor()
    pqc = PQCReadinessEngine()
    sim = MigrationSimulator()
    veri = MigrationVerificationEngine()
    
    # ---------------------------------------------------------
    # STEP 1: Inventory Discovery (From Phase 19/8 Passive Sensors)
    # ---------------------------------------------------------
    print("[*] STEP 1: Discovering Cryptography via Passive Telemetry...")
    inv.discover_asset("CERTIFICATE", "RSA-2048", "MTA-01", "ClientGroup-Modern", "PCAP-001")
    inv.discover_asset("CERTIFICATE", "RSA-2048", "MTA-01", "ClientGroup-Legacy-Java", "PCAP-002")
    inv.discover_asset("CERTIFICATE", "ECDSA-P256", "MTA-02", "ClientGroup-Modern", "PCAP-003")
    
    print(f"    -> Discovered {len(inv.crypto_assets)} cryptographic dependency links.")
    
    # ---------------------------------------------------------
    # STEP 2: Crypto Agility & PQC Readiness Assessment
    # ---------------------------------------------------------
    print("\n[*] STEP 2: Assessing PQC Readiness and Cryptographic Agility...")
    pqc_state = pqc.assess_asset("MTA-01", inv)
    agil_state = agility.assess("MTA-01", inv)
    
    print(f"    [MTA-01] PQC Status: {pqc_state['pqc_status']} (HNDL Exposure: {pqc_state['hndl_exposure']})")
    print(f"    [MTA-01] Agility Score: {agil_state.overall_agility} (Visibility: {agil_state.dependency_visibility})")
    
    # ---------------------------------------------------------
    # STEP 3: Migration Simulation (Digital Twin)
    # ---------------------------------------------------------
    print("\n[*] STEP 3: Simulating Migration to NIST FIPS-204 (ML-DSA)...")
    print("    Target: Replace MTA-01 RSA-2048 with ML-DSA-65")
    
    scenario = sim.simulate("MTA-01", "ML-DSA-65", inv)
    
    if scenario.blockers:
        print("    [!] MIGRATION BLOCKERS DETECTED:")
        for blocker in scenario.blockers:
            print(f"        - {blocker}")
    print(f"    -> Simulation Status: {scenario.status}. Requires legacy client remediation first.")
    
    # ---------------------------------------------------------
    # STEP 4: Production Deployment & Verification
    # ---------------------------------------------------------
    print("\n[*] STEP 4: Pre-Production Verification (After Legacy Clients Upgraded)...")
    
    # Simulate intercepting traffic post-migration attempt
    print("    -> Ingesting Verification PCAP: 'post_migration_verify.pcap'")
    
    # Scenario A: Successful migration
    print("\n    [Test A: Clean Cutover]")
    res_a = veri.verify(scenario.scenario_id, "ML-DSA-65", ["ML-DSA-65"], "PCAP-VERIFY-01")
    print(f"    Status: {res_a.status}")
    
    # Scenario B: Failed migration (Fallback still active)
    print("\n    [Test B: Configuration Drift / Hybrid Fallback Detected]")
    res_b = veri.verify(scenario.scenario_id, "ML-DSA-65", ["ML-DSA-65", "RSA-2048"], "PCAP-VERIFY-02")
    print(f"    Status: {res_b.status}")
    
    print("\n[✓] Phase 21 Execution Complete. The enterprise is now managing Cryptographic Agility.")

def main():
    parser = argparse.ArgumentParser(description="Phase 21 - Cryptographic Agility & PQC")
    parser.add_argument("command", choices=["serve", "demo"], help="Command to run", default="demo", nargs="?")
    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Phase 21 Crypto Agility API on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("FastAPI not installed. Run 'demo' instead.")
    elif args.command == "demo":
        run_phase21_demo()

if __name__ == "__main__":
    main()