import json
import uuid
import time
import logging
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase16 - %(message)s")
logger = logging.getLogger("Digital-Twin-Simulation")

try:
    from fastapi import FastAPI, HTTPException
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. Phase 16 API mode disabled.")

# --- DATA MODELS: DIGITAL TWIN ---

@dataclass
class ConfigurationState:
    """Represents a configuration property, explicitly tagging confidence and source."""
    property_name: str
    value: Any
    state_type: str # OBSERVED, INFERRED, CONFIGURED, SIMULATED
    confidence: float
    source_evidence: List[str] = field(default_factory=list)

@dataclass
class TwinAsset:
    """A modeled asset within the digital twin based on Phase 1-14 intelligence."""
    asset_id: str
    role: str
    exposure: str # INTERNET, INTERNAL
    tls_versions: Dict[str, ConfigurationState] = field(default_factory=dict)
    certificates: Dict[str, ConfigurationState] = field(default_factory=dict)
    client_dependencies: Set[str] = field(default_factory=set) # Known JA4s/Client Groups

@dataclass
class ClientGroup:
    """Represents a population of clients connecting to assets."""
    group_id: str
    description: str
    supported_tls: Set[str]
    historical_session_count: int

@dataclass
class DigitalTwinSnapshot:
    """A point-in-time snapshot of the enterprise cryptographic posture."""
    snapshot_id: str
    created_at: datetime
    assets: Dict[str, TwinAsset] = field(default_factory=dict)
    clients: Dict[str, ClientGroup] = field(default_factory=dict)
    posture_metrics: Dict[str, Any] = field(default_factory=dict)

# --- DATA MODELS: SIMULATION ---

@dataclass
class ScenarioChange:
    target_asset_id: str
    property_name: str
    new_value: Any
    change_type: str # UPDATE, DELETE, ROTATE

@dataclass
class SimulatedScenario:
    scenario_id: str
    name: str
    base_snapshot_id: str
    changes: List[ScenarioChange]
    status: str = "DRAFT"

@dataclass
class ImpactAnalysis:
    scenario_id: str
    assets_affected: int
    clients_broken: List[str]
    historical_sessions_affected: int
    security_posture_change: str
    residual_exposure: str
    blast_radius_score: float
    explanation: List[str] = field(default_factory=list)

# --- ENGINE IMPLEMENTATIONS ---

class DigitalTwinManager:
    """Manages the creation and retrieval of infrastructure snapshots."""
    
    def __init__(self):
        self.snapshots: Dict[str, DigitalTwinSnapshot] = {}

    def create_snapshot(self) -> DigitalTwinSnapshot:
        """Mocks retrieving graph data from Phase 14 to build the twin."""
        logger.info("Building Digital Twin Snapshot from Security Knowledge Graph...")
        
        snap_id = f"TWIN-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
        snapshot = DigitalTwinSnapshot(snapshot_id=snap_id, created_at=datetime.now(timezone.utc))
        
        # Mock Asset: Public MTA
        mta01 = TwinAsset(asset_id="MTA-01", role="MTA", exposure="INTERNET")
        mta01.tls_versions["TLS1.1"] = ConfigurationState("TLS1.1", True, "OBSERVED", 1.0, ["EV-912"])
        mta01.tls_versions["TLS1.2"] = ConfigurationState("TLS1.2", True, "OBSERVED", 1.0, ["EV-913"])
        mta01.tls_versions["TLS1.3"] = ConfigurationState("TLS1.3", True, "OBSERVED", 1.0, ["EV-914"])
        mta01.certificates["CERT-A"] = ConfigurationState("Active_Cert", "CERT-A", "OBSERVED", 0.99)
        mta01.client_dependencies = {"Modern_MTA_Fleet", "Legacy_App_Server", "Unknown_External_Scanners"}
        
        snapshot.assets[mta01.asset_id] = mta01
        
        # Mock Client Populations
        snapshot.clients["Modern_MTA_Fleet"] = ClientGroup("Modern_MTA_Fleet", "Standard O365/Google MTAs", {"TLS1.2", "TLS1.3"}, 18500)
        snapshot.clients["Legacy_App_Server"] = ClientGroup("Legacy_App_Server", "Internal billing app (Java 7)", {"TLS1.1"}, 218)
        snapshot.clients["Unknown_External_Scanners"] = ClientGroup("Unknown_External_Scanners", "Internet noise", {"TLS1.0", "TLS1.1", "TLS1.2"}, 450)
        
        self.snapshots[snap_id] = snapshot
        return snapshot

class WhatIfSimulator:
    """Evaluates the blast radius and security impact of hypothetical configurations."""
    
    def __init__(self, twin_manager: DigitalTwinManager):
        self.twin_manager = twin_manager

    def simulate(self, scenario: SimulatedScenario) -> ImpactAnalysis:
        logger.info(f"Executing Simulation for Scenario: {scenario.name}")
        snapshot = self.twin_manager.snapshots.get(scenario.base_snapshot_id)
        if not snapshot:
            raise ValueError("Base snapshot not found.")

        broken_clients = []
        sessions_lost = 0
        assets_affected = 0
        explanation = []

        # 1. Apply simulated changes to a deep copy of the state
        simulated_assets = {k: TwinAsset(**asdict(v)) for k, v in snapshot.assets.items()}
        
        for change in scenario.changes:
            asset = simulated_assets.get(change.target_asset_id)
            if not asset:
                continue
            
            assets_affected += 1
            explanation.append(f"Applied change: {change.property_name} -> {change.new_value} on {asset.asset_id}")
            
            # Example Logic: Disabling a TLS version
            if change.property_name.startswith("tls_versions"):
                target_version = change.property_name.split(".")[-1]
                if target_version in asset.tls_versions and change.new_value is False:
                    explanation.append(f"Removed {target_version} support from {asset.asset_id}.")
                    
                    # 2. Blast Radius Analysis (Check dependent clients)
                    for client_id in asset.client_dependencies:
                        client = snapshot.clients.get(client_id)
                        if client:
                            # If the client ONLY supports the disabled version, it breaks.
                            remaining_versions = client.supported_tls - {target_version}
                            if not remaining_versions:
                                broken_clients.append(client.group_id)
                                sessions_lost += client.historical_session_count
                                explanation.append(f"Client Group '{client_id}' is INCOMPATIBLE. Loses connection capability (Hist sessions: {client.historical_session_count}).")
                            else:
                                explanation.append(f"Client Group '{client_id}' successfully degrades/upgrades to {remaining_versions}.")

        # 3. Security Posture Recalculation
        posture_change = "IMPROVED" if broken_clients else "NEUTRAL"
        residual = "LOW" if not broken_clients else "HIGH_COMPATIBILITY_RISK"
        
        blast_score = (len(broken_clients) * 0.5) + (assets_affected * 0.2)

        return ImpactAnalysis(
            scenario_id=scenario.scenario_id,
            assets_affected=assets_affected,
            clients_broken=broken_clients,
            historical_sessions_affected=sessions_lost,
            security_posture_change=posture_change,
            residual_exposure=residual,
            blast_radius_score=blast_score,
            explanation=explanation
        )

class AttackPathAnalyzer:
    """Identifies potential exploitation routes based on modeled cryptographic weaknesses."""
    
    def generate_paths(self, snapshot: DigitalTwinSnapshot) -> List[Dict[str, Any]]:
        logger.info("Generating Attack Path Hypotheses...")
        paths = []
        
        for asset in snapshot.assets.values():
            if asset.exposure == "INTERNET":
                # Check for weak crypto boundaries
                has_weak_tls = any(v.value is True and "1.1" in k for k, v in asset.tls_versions.items())
                if has_weak_tls:
                    paths.append({
                        "path_id": f"PATH-{uuid.uuid4().hex[:6].upper()}",
                        "nodes": ["INTERNET", asset.asset_id, "Internal Email Subsystem"],
                        "vulnerability": "TLS 1.1 Downgrade / Eavesdropping",
                        "status": "HYPOTHETICAL",
                        "evidence": [f"OBSERVED TLS1.1 on {asset.asset_id}"]
                    })
        return paths

class OptimizationEngine:
    """Compares multiple simulated scenarios to find the best remediation tradeoff."""
    
    def compare_scenarios(self, analyses: List[ImpactAnalysis]) -> Dict[str, Any]:
        logger.info("Running Multi-Objective Optimization Matrix...")
        
        comparison = []
        for a in analyses:
            score = 100 - (a.blast_radius_score * 10) - (len(a.clients_broken) * 20)
            comparison.append({
                "scenario_id": a.scenario_id,
                "compatibility_impact_sessions": a.historical_sessions_affected,
                "security_posture": a.security_posture_change,
                "viability_score": max(0, score)
            })
            
        # Sort by best viability (highest security, lowest breakage)
        comparison.sort(key=lambda x: x["viability_score"], reverse=True)
        return {"ranked_options": comparison, "recommended": comparison[0]["scenario_id"] if comparison else None}

if HAS_FASTAPI:
    app = FastAPI(title="Phase 16 - Digital Twin & Simulation API", version="16.0.0")
    
    twin_mgr = DigitalTwinManager()
    simulator = WhatIfSimulator(twin_mgr)
    attack_analyzer = AttackPathAnalyzer()
    
    @app.post("/api/v1/twin/snapshot", tags=["Digital Twin"])
    def create_twin_snapshot():
        snap = twin_mgr.create_snapshot()
        return asdict(snap)

    @app.post("/api/v1/simulations/run", tags=["Simulation"])
    def run_simulation(scenario: SimulatedScenario):
        if scenario.base_snapshot_id not in twin_mgr.snapshots:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        
        impact = simulator.simulate(scenario)
        return asdict(impact)
        
    @app.get("/api/v1/attack-paths", tags=["Security Optimization"])
    def get_attack_paths(snapshot_id: str):
        snap = twin_mgr.snapshots.get(snapshot_id)
        if not snap:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return {"attack_paths": attack_analyzer.generate_paths(snap)}

def run_phase16_demo():
    print("\n" + "="*70)
    print(" PHASE 16: DIGITAL TWIN, WHAT-IF SIMULATION & OPTIMIZATION")
    print("="*70 + "\n")

    twin_mgr = DigitalTwinManager()
    simulator = WhatIfSimulator(twin_mgr)
    opt_engine = OptimizationEngine()
    attack_analyzer = AttackPathAnalyzer()

    # 1. Build Digital Twin
    print("[*] 1. Constructing Infrastructure Digital Twin from Phase 14 Graph...")
    snapshot = twin_mgr.create_snapshot()
    print(f"    -> Twin ID: {snapshot.snapshot_id}")
    print(f"    -> Assets Modeled: {len(snapshot.assets)}")
    print(f"    -> Client Populations Modeled: {len(snapshot.clients)}\n")

    # 2. Attack Path Analysis
    print("[*] 2. Executing Attack Path Discovery...")
    paths = attack_analyzer.generate_paths(snapshot)
    for p in paths:
        print(f"    -> [!] POTENTIAL PATH: {' -> '.join(p['nodes'])}")
        print(f"       Vulnerability: {p['vulnerability']}")
        print(f"       Basis: {p['evidence'][0]}\n")

    # 3. What-If Scenarios
    print("[*] 3. Defining What-If Remediation Scenarios...")
    
    scenario_a = SimulatedScenario(
        scenario_id="SCN-DISABLE-TLS11",
        name="Hard-Disable TLS 1.1 Immediately",
        base_snapshot_id=snapshot.snapshot_id,
        changes=[ScenarioChange("MTA-01", "tls_versions.TLS1.1", False, "UPDATE")]
    )
    
    # 4. Simulation Execution
    print(f"[*] 4. Simulating Impact: {scenario_a.name}")
    impact_a = simulator.simulate(scenario_a)
    
    print("\n    [SIMULATION RESULTS]")
    for line in impact_a.explanation:
        print(f"      - {line}")
        
    print(f"\n    [BLAST RADIUS]")
    print(f"      - Incompatible Clients: {len(impact_a.clients_broken)} ({', '.join(impact_a.clients_broken)})")
    print(f"      - Historical Sessions Lost: {impact_a.historical_sessions_affected}")
    print(f"      - Residual Posture: {impact_a.residual_exposure}\n")

    # 5. Security Optimization (Mocking a second scenario for comparison)
    print("[*] 5. Running Multi-Objective Optimization...")
    impact_b = ImpactAnalysis("SCN-MIGRATE-FIRST", 1, [], 0, "IMPROVED", "LOW", 0.5, ["Migrated legacy clients prior to cutover."])
    
    optimization_matrix = opt_engine.compare_scenarios([impact_a, impact_b])
    
    print("    [TRADE-OFF MATRIX]")
    for opt in optimization_matrix["ranked_options"]:
        print(f"      -> Scenario: {opt['scenario_id']} | Viability Score: {opt['viability_score']:.1f} | Breakage: {opt['compatibility_impact_sessions']} sessions")
        
    print(f"\n[✓] Phase 16 Complete. Optimal Recommendation: {optimization_matrix['recommended']}")


def main():
    parser = argparse.ArgumentParser(description="Phase 16 - Digital Twin & Simulation")
    parser.add_argument("command", choices=["serve", "demo"], help="Command to run", default="demo", nargs="?")
    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Phase 16 Simulation API on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("FastAPI not installed. Run 'demo' instead.")
    elif args.command == "demo":
        run_phase16_demo()

if __name__ == "__main__":
    main()