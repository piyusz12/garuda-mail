import json
import uuid
import time
import logging
import argparse
import numpy as np
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase14 - %(message)s")
logger = logging.getLogger("Advanced-Intelligence")

try:
    from fastapi import FastAPI, HTTPException
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. API mode disabled.")

# --- DATA MODELS ---

@dataclass
class CanonicalEntity:
    """A resolved, canonical entity in the Security Knowledge Graph."""
    entity_id: str
    entity_type: str # ASSET, IP, DOMAIN, CERTIFICATE, JA4, SESSION, INCIDENT
    value: str
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphRelationship:
    """A directed edge in the Security Knowledge Graph."""
    source_id: str
    target_id: str
    relationship_type: str # CONNECTED_TO, PRESENTED_CERTIFICATE, USED_JA4, TRIGGERED
    weight: float = 1.0
    first_observed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_observed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class ThreatIndicator:
    """External Threat Intelligence Indicator."""
    indicator_id: str
    indicator_type: str
    value: str
    source: str
    confidence: int # 0 to 100
    first_seen: datetime
    last_updated: datetime
    expires_at: datetime
    is_active: bool = True
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class VectorEmbedding:
    """Represents a behavioral embedding for Similarity Search."""
    entity_id: str
    entity_type: str
    vector: np.ndarray
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

# --- THREAT INTELLIGENCE ---

class ThreatIntelManager:
    """Ingests, normalizes, and manages lifecycle of external threat intelligence."""
    
    def __init__(self):
        self.indicators: Dict[str, ThreatIndicator] = {}
        
    def ingest_feed(self, source: str, data: List[Dict[str, Any]]):
        logger.info(f"Ingesting {len(data)} indicators from {source}...")
        now = datetime.now(timezone.utc)
        
        for item in data:
            indicator_id = f"TI-{uuid.uuid4().hex[:8]}"
            expiry = now + timedelta(days=item.get("ttl_days", 30))
            
            ti = ThreatIndicator(
                indicator_id=indicator_id,
                indicator_type=item["type"],
                value=item["value"],
                source=source,
                confidence=item.get("confidence", 50),
                first_seen=now,
                last_updated=now,
                expires_at=expiry,
                context=item.get("context", {})
            )
            # Use value as a quick lookup key for the prototype
            self.indicators[ti.value] = ti
            
    def query(self, value: str) -> Optional[ThreatIndicator]:
        ti = self.indicators.get(value)
        if not ti:
            return None
        if datetime.now(timezone.utc) > ti.expires_at:
            ti.is_active = False
            return None
        return ti

# --- SECURITY KNOWLEDGE GRAPH ---

class SecurityKnowledgeGraph:
    """
    In-memory graph database correlating entities across multiple PCAPs and timeframes.
    In production, this is backed by Neo4j or Amazon Neptune.
    """
    def __init__(self):
        self.nodes: Dict[str, CanonicalEntity] = {}
        # Adjacency list: node_id -> {relationship_type -> set(target_ids)}
        self.edges: Dict[str, Dict[str, Set[str]]] = {}
        # Reverse lookup for Entity Resolution
        self._value_lookup: Dict[str, str] = {}

    def resolve_entity(self, entity_type: str, value: str) -> CanonicalEntity:
        """Entity Resolution: Maps an observable to a Canonical Entity."""
        lookup_key = f"{entity_type}:{value}"
        if lookup_key in self._value_lookup:
            node_id = self._value_lookup[lookup_key]
            self.nodes[node_id].last_seen = datetime.now(timezone.utc)
            return self.nodes[node_id]
            
        # Create new entity
        entity_id = f"ENT-{uuid.uuid4().hex[:8]}"
        entity = CanonicalEntity(entity_id=entity_id, entity_type=entity_type, value=value)
        self.nodes[entity_id] = entity
        self._value_lookup[lookup_key] = entity_id
        self.edges[entity_id] = {}
        return entity

    def add_relationship(self, source: CanonicalEntity, target: CanonicalEntity, rel_type: str):
        """Creates a directed edge between two canonical entities."""
        if rel_type not in self.edges[source.entity_id]:
            self.edges[source.entity_id][rel_type] = set()
        self.edges[source.entity_id][rel_type].add(target.entity_id)

    def get_neighborhood(self, entity_id: str, depth: int = 1) -> Dict[str, Any]:
        """Traverses the graph to find connected campaigns and blast radius."""
        if entity_id not in self.nodes:
            return {}
            
        visited = set()
        queue = [(entity_id, 0)]
        subgraph_nodes = {}
        subgraph_edges = []
        
        while queue:
            current_id, current_depth = queue.pop(0)
            if current_id in visited or current_depth > depth:
                continue
                
            visited.add(current_id)
            subgraph_nodes[current_id] = asdict(self.nodes[current_id])
            
            for rel_type, targets in self.edges.get(current_id, {}).items():
                for target_id in targets:
                    subgraph_edges.append({"source": current_id, "target": target_id, "type": rel_type})
                    if target_id not in visited:
                        queue.append((target_id, current_depth + 1))
                        
        return {"nodes": subgraph_nodes, "edges": subgraph_edges}

# --- VECTOR SIMILARITY ENGINE ---

class VectorSimilarityEngine:
    """Uses Cosine Similarity on Phase 6 AI latent embeddings to find related behaviors."""
    def __init__(self):
        self.embeddings: List[VectorEmbedding] = []
        
    def add_embedding(self, entity_id: str, entity_type: str, vector: np.ndarray):
        # Normalize the vector for faster cosine similarity via dot product
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector = vector / norm
        self.embeddings.append(VectorEmbedding(entity_id, entity_type, vector))
        
    def search(self, query_vector: np.ndarray, top_k: int = 3, min_similarity: float = 0.8) -> List[Dict[str, Any]]:
        if not self.embeddings:
            return []
            
        norm = np.linalg.norm(query_vector)
        if norm > 0:
            query_vector = query_vector / norm
            
        results = []
        for emb in self.embeddings:
            sim = float(np.dot(query_vector, emb.vector))
            if sim >= min_similarity:
                results.append({"entity_id": emb.entity_id, "type": emb.entity_type, "similarity": round(sim, 3)})
                
        # Sort by highest similarity
        return sorted(results, key=lambda x: x["similarity"], reverse=True)[:top_k]

# --- THREAT HUNTING WORKBENCH ---

class ThreatHuntingWorkbench:
    """Executes predefined and structured queries against the Knowledge Graph and Intel Store."""
    def __init__(self, graph: SecurityKnowledgeGraph, intel: ThreatIntelManager):
        self.graph = graph
        self.intel = intel
        
    def hunt_rare_ja4_on_critical_assets(self) -> List[Dict[str, Any]]:
        """HUNT-002: Identifies unusual JA4s connected to important MTAs."""
        results = []
        for node in self.graph.nodes.values():
            if node.entity_type == "JA4":
                # Check connections
                assets = self.graph.edges.get(node.entity_id, {}).get("USED_BY", set())
                # Heuristic: Used by few assets, but the assets are critical
                if 0 < len(assets) <= 2:
                    asset_details = [self.graph.nodes[a].value for a in assets]
                    results.append({
                        "ja4": node.value,
                        "associated_assets": asset_details,
                        "risk_hypothesis": "Targeted or emerging client behavior"
                    })
        return results

# --- API LAYER ---

if HAS_FASTAPI:
    app = FastAPI(title="Phase 14 - Advanced Forensic Intelligence", version="14.0.0")
    
    graph = SecurityKnowledgeGraph()
    intel = ThreatIntelManager()
    vector_store = VectorSimilarityEngine()
    hunter = ThreatHuntingWorkbench(graph, intel)

    @app.get("/api/v1/intelligence/graph/{entity_type}/{value}", tags=["Graph"])
    def get_entity_graph(entity_type: str, value: str, depth: int = 2):
        """Retrieve the blast radius / neighborhood for a given entity."""
        lookup_key = f"{entity_type}:{value}"
        if lookup_key not in graph._value_lookup:
            raise HTTPException(status_code=404, detail="Entity not found")
            
        entity_id = graph._value_lookup[lookup_key]
        return graph.get_neighborhood(entity_id, depth)

    @app.get("/api/v1/intelligence/hunts/run", tags=["Hunting"])
    def execute_hunt(hunt_id: str):
        if hunt_id == "HUNT-002":
            return hunter.hunt_rare_ja4_on_critical_assets()
        raise HTTPException(status_code=400, detail="Unknown Hunt ID")


def run_phase14_demo():
    print("\n" + "="*70)
    print(" PHASE 14: ADVANCED CRYPTOGRAPHIC INTELLIGENCE & GRAPH DEMO")
    print("="*70 + "\n")
    
    graph = SecurityKnowledgeGraph()
    intel = ThreatIntelManager()
    vectors = VectorSimilarityEngine()
    
    # 1. Ingest Threat Intelligence
    print("[*] 1. Ingesting External Threat Intelligence Feeds...")
    intel.ingest_feed("OSINT-Feed-A", [
        {"type": "JA4", "value": "t13d1516h2_8daaf6152771_a56c5b9", "confidence": 85, "context": {"campaign": "Cobalt Strike"}},
        {"type": "CERT_SHA256", "value": "a1b2c3d4...", "confidence": 95, "context": {"description": "Known malicious cert"}}
    ])
    print(f"    Loaded {len(intel.indicators)} active indicators.\n")
    
    # 2. Entity Resolution & Cross-PCAP Graph Building
    print("[*] 2. Building Security Knowledge Graph across multiple PCAP telemetry streams...")
    
    # PCAP 1 (Yesterday)
    asset1 = graph.resolve_entity("ASSET", "smtp01.enterprise.com")
    ja4_a = graph.resolve_entity("JA4", "t13d1516h2_8daaf6152771_a56c5b9") # Malicious JA4
    cert_a = graph.resolve_entity("CERTIFICATE", "cert_valid_sha256")
    
    graph.add_relationship(ja4_a, asset1, "USED_BY")
    graph.add_relationship(asset1, cert_a, "PRESENTED_CERTIFICATE")
    
    # PCAP 2 (Today - Cross-PCAP Correlation)
    asset2 = graph.resolve_entity("ASSET", "mta-gateway.europe.com")
    cert_b = graph.resolve_entity("CERTIFICATE", "cert_expired_sha256")
    
    graph.add_relationship(ja4_a, asset2, "USED_BY")
    graph.add_relationship(asset2, cert_b, "PRESENTED_CERTIFICATE")
    
    print(f"    Graph contains {len(graph.nodes)} unique canonical entities.\n")
    
    # 3. Graph Traversal & Blast Radius
    print("[*] 3. Correlating Activity: Blast Radius for highly-suspicious JA4...")
    ti_match = intel.query(ja4_a.value)
    if ti_match:
        print(f"    [!] THREAT INTEL MATCH: {ti_match.value} (Confidence: {ti_match.confidence}%)")
        print(f"        Context: {ti_match.context}")
        
    neighborhood = graph.get_neighborhood(ja4_a.entity_id, depth=2)
    print("\n    Correlated Campaign / Cluster:")
    for edge in neighborhood["edges"]:
        src = neighborhood["nodes"][edge["source"]]["value"]
        tgt = neighborhood["nodes"][edge["target"]]["value"]
        print(f"      - {src} --[{edge['type']}]--> {tgt}")
        
    # 4. Vector Similarity Search (Predictive / Unknown Unknowns)
    print("\n[*] 4. Executing Latent Space Similarity Search (Finding related un-signatured behaviors)...")
    # Simulate embedding vectors generated by Phase 6 Autoencoder
    vectors.add_embedding("FLOW-881", "SESSION", np.array([0.1, 0.8, -0.2, 0.4]))
    vectors.add_embedding("FLOW-882", "SESSION", np.array([0.1, 0.79, -0.21, 0.39])) # Highly similar
    vectors.add_embedding("FLOW-883", "SESSION", np.array([-0.9, 0.1, 0.8, 0.0]))   # Different
    
    query_vector = np.array([0.1, 0.8, -0.2, 0.4])
    similar_sessions = vectors.search(query_vector, top_k=2)
    
    print(f"    Querying Graph for sessions behaving similar to FLOW-881:")
    for res in similar_sessions:
        print(f"      -> {res['entity_id']} (Similarity: {res['similarity'] * 100:.1f}%)")

    print("\n[✓] Phase 14 Execution Complete. Isolated PCAP sessions are now correlated intelligence.")


if __name__ == "__main__":
    import sys
    parser = argparse.ArgumentParser(description="Phase 14 - Advanced Threat Intelligence")
    parser.add_argument("command", choices=["serve", "demo"], help="Command to run", nargs="?", default="demo")
    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Phase 14 Intelligence API on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("FastAPI not installed. Run 'demo' instead.")
    elif args.command == "demo":
        run_phase14_demo()