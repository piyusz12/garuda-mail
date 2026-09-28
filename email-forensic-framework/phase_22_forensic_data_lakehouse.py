import json
import uuid
import time
import hashlib
import logging
import argparse
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase22 - %(message)s")
logger = logging.getLogger("Forensic-Lakehouse")

try:
    from fastapi import FastAPI, HTTPException, Depends
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. Lakehouse API mode disabled.")

# --- DATA MODELS ---

@dataclass
class LakehouseObject:
    """Universal record for Bronze, Silver, and Gold data layers."""
    object_id: str
    layer: str # BRONZE, SILVER, GOLD
    entity_type: str # PCAP, SESSION, FINDING, ASSET_POSTURE
    timestamp: datetime
    data: Dict[str, Any]
    source: str
    tenant_id: str = "default-tenant"
    schema_version: str = "1.0"
    sha256: str = ""
    is_deleted: bool = False

@dataclass
class LineageNode:
    """Tracks the provenance of data from Findings back to raw PCAPs."""
    object_id: str
    parents: List[str] = field(default_factory=list)
    children: List[str] = field(default_factory=list)

@dataclass
class LegalHold:
    """Prevents deletion of evidence tied to an ongoing investigation."""
    hold_id: str
    case_id: str
    reason: str
    objects: Set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    active: bool = True



class LineageGraph:
    """Maintains the traceability from analytical conclusions back to raw bits."""
    def __init__(self):
        self.nodes: Dict[str, LineageNode] = {}

    def record_derivation(self, source_id: str, derived_id: str):
        """Records that `derived_id` was generated from `source_id`."""
        if source_id not in self.nodes:
            self.nodes[source_id] = LineageNode(source_id)
        if derived_id not in self.nodes:
            self.nodes[derived_id] = LineageNode(derived_id)
            
        self.nodes[source_id].children.append(derived_id)
        self.nodes[derived_id].parents.append(source_id)

    def trace_lineage(self, object_id: str) -> Dict[str, List[str]]:
        """Walks backwards to find all root sources (e.g., PCAPs)."""
        if object_id not in self.nodes:
            return {"object": object_id, "parents": []}
            
        lineage_path = []
        queue = [object_id]
        visited = set()
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            node = self.nodes.get(current)
            if node and node.parents:
                for parent in node.parents:
                    lineage_path.append(f"{current} <== {parent}")
                    queue.append(parent)
                    
        return {"object": object_id, "trace": lineage_path}



class RetentionManager:
    """Manages Legal Holds and prevents accidental evidence destruction."""
    def __init__(self):
        self.holds: Dict[str, LegalHold] = {}
        
    def create_hold(self, case_id: str, reason: str, object_ids: List[str]) -> LegalHold:
        hold_id = f"HOLD-{uuid.uuid4().hex[:6].upper()}"
        hold = LegalHold(hold_id, case_id, reason, set(object_ids))
        self.holds[hold_id] = hold
        logger.info(f"Created Legal Hold {hold_id} for Case {case_id} covering {len(object_ids)} objects.")
        return hold

    def can_delete(self, object_id: str) -> bool:
        """Evaluates if an object is currently protected by an active Legal Hold."""
        for hold in self.holds.values():
            if hold.active and object_id in hold.objects:
                if hold.expires_at and hold.expires_at < datetime.now(timezone.utc):
                    continue # Hold expired
                return False
        return True



class ForensicDataLake:
    """
    The unified storage engine.
    Partitions data logically into Bronze (Raw), Silver (Normalized), and Gold (Analytics).
    """
    def __init__(self, lineage: LineageGraph, retention: RetentionManager):
        self.storage: Dict[str, LakehouseObject] = {}
        self.lineage = lineage
        self.retention = retention

    def ingest_bronze(self, raw_data: bytes, source: str, entity_type: str = "PCAP") -> str:
        """Stores immutable raw evidence."""
        obj_id = f"RAW-{uuid.uuid4().hex[:8].upper()}"
        sha256 = hashlib.sha256(raw_data).hexdigest()
        
        obj = LakehouseObject(
            object_id=obj_id,
            layer="BRONZE",
            entity_type=entity_type,
            timestamp=datetime.now(timezone.utc) - timedelta(days=random_offset()), # Simulated history
            data={"s3_uri": f"s3://datalake/bronze/{obj_id}.pcap", "size": len(raw_data)},
            source=source,
            sha256=sha256
        )
        self.storage[obj_id] = obj
        logger.debug(f"[Lakehouse] Ingested BRONZE {entity_type}: {obj_id}")
        return obj_id

    def ingest_silver(self, source_raw_id: str, normalized_data: Dict[str, Any], entity_type: str) -> str:
        """Stores parsed, normalized forensic events."""
        obj_id = f"NORM-{uuid.uuid4().hex[:8].upper()}"
        
        # Inherit timestamp from parent or use current
        parent = self.storage.get(source_raw_id)
        ts = parent.timestamp if parent else datetime.now(timezone.utc)
        
        obj = LakehouseObject(
            object_id=obj_id,
            layer="SILVER",
            entity_type=entity_type,
            timestamp=ts,
            data=normalized_data,
            source="normalization-pipeline"
        )
        self.storage[obj_id] = obj
        self.lineage.record_derivation(source_raw_id, obj_id)
        logger.debug(f"[Lakehouse] Ingested SILVER {entity_type}: {obj_id}")
        return obj_id

    def ingest_gold(self, source_silver_ids: List[str], aggregated_data: Dict[str, Any], entity_type: str) -> str:
        """Stores high-level analytical insights and posture snapshots."""
        obj_id = f"ANALYSIS-{uuid.uuid4().hex[:8].upper()}"
        
        obj = LakehouseObject(
            object_id=obj_id,
            layer="GOLD",
            entity_type=entity_type,
            timestamp=datetime.now(timezone.utc),
            data=aggregated_data,
            source="analytics-engine"
        )
        self.storage[obj_id] = obj
        for s_id in source_silver_ids:
            self.lineage.record_derivation(s_id, obj_id)
        
        logger.debug(f"[Lakehouse] Ingested GOLD {entity_type}: {obj_id}")
        return obj_id

    def delete_object(self, object_id: str, requested_by: str) -> bool:
        """Attempts to soft-delete an object, respecting Legal Holds."""
        if object_id not in self.storage:
            raise ValueError("Object not found")
            
        if not self.retention.can_delete(object_id):
            logger.error(f"[Retention] 🛑 DENIED: Cannot delete {object_id}. Active Legal Hold in place.")
            return False
            
        self.storage[object_id].is_deleted = True
        logger.info(f"[Retention] Deleted {object_id} (Requested by: {requested_by})")
        return True



class SearchEngine:
    """Parses custom Forensic Query Language (FQL) and searches the Lakehouse."""
    def __init__(self, lake: ForensicDataLake):
        self.lake = lake

    def execute_fql(self, query: str) -> List[Dict[str, Any]]:
        """
        Mock implementation of a Forensic DSL parser.
        Example: FROM sessions WHERE asset = 'MTA-07'
        """
        logger.info(f"[Search Engine] Executing Query: {query}")
        
        # Extremely simplified parsing for the demo
        parts = query.lower().split()
        if "from" not in parts:
            return []
            
        entity_target = parts[parts.index("from") + 1].upper() # e.g., SESSIONS
        
        results = []
        for obj in self.lake.storage.values():
            if obj.is_deleted:
                continue
                
            # Naive entity match (e.g., matching 'sessions' to 'SESSION')
            if entity_target.startswith(obj.entity_type.lower()) or obj.entity_type.lower().startswith(entity_target):
                
                # Apply WHERE filters naively
                match = True
                if "where" in parts:
                    try:
                        where_idx = parts.index("where")
                        key = parts[where_idx + 1]
                        val = parts[where_idx + 3].strip("'\"")
                        if str(obj.data.get(key, "")).lower() != val.lower():
                            match = False
                    except (IndexError, ValueError):
                        pass # Ignore malformed WHERE in demo
                        
                if match:
                    results.append({
                        "object_id": obj.object_id,
                        "layer": obj.layer,
                        "timestamp": obj.timestamp.isoformat(),
                        "data": obj.data
                    })
                    
        return results



class TimeMachineEngine:
    """Reconstructs the cryptographic posture as it existed at a specific point in time."""
    def __init__(self, lake: ForensicDataLake):
        self.lake = lake

    def get_posture_as_of(self, target_date: datetime) -> Dict[str, Any]:
        """Calculates statistics based only on data existing prior to target_date."""
        logger.info(f"[Time Machine] Reconstructing enterprise posture as of {target_date.date()}...")
        
        stats = {"tls1_3": 0, "tls1_2": 0, "deprecated": 0, "total_sessions": 0}
        
        for obj in self.lake.storage.values():
            if obj.is_deleted or obj.layer != "SILVER" or obj.entity_type != "SESSION":
                continue
                
            if obj.timestamp <= target_date:
                stats["total_sessions"] += 1
                tls_ver = obj.data.get("tls_version", "")
                
                if "1.3" in tls_ver:
                    stats["tls1_3"] += 1
                elif "1.2" in tls_ver:
                    stats["tls1_2"] += 1
                elif "1.1" in tls_ver or "1.0" in tls_ver:
                    stats["deprecated"] += 1

        # Calculate percentages
        if stats["total_sessions"] > 0:
            for k in ["tls1_3", "tls1_2", "deprecated"]:
                stats[f"{k}_pct"] = round((stats[k] / stats["total_sessions"]) * 100, 1)
                
        return {"as_of_date": target_date.isoformat(), "metrics": stats}



def random_offset() -> int:
    """Helper for demo to scatter data across the last 3 years."""
    import random
    return random.randint(1, 1000)

if HAS_FASTAPI:
    app = FastAPI(title="Phase 22 - Forensic Data Lakehouse", version="22.0.0")
    
    lineage_tracker = LineageGraph()
    retention_mgr = RetentionManager()
    data_lake = ForensicDataLake(lineage_tracker, retention_mgr)
    search_engine = SearchEngine(data_lake)
    time_machine = TimeMachineEngine(data_lake)

    @app.post("/api/v1/search", tags=["Enterprise Search"])
    def unified_search(query: str):
        return search_engine.execute_fql(query)

    @app.get("/api/v1/data/{object_id}/lineage", tags=["Data Governance"])
    def get_lineage(object_id: str):
        return lineage_tracker.trace_lineage(object_id)

    @app.get("/api/v1/posture", tags=["Historical Analytics"])
    def get_historical_posture(as_of: str):
        try:
            target_date = datetime.fromisoformat(as_of)
            if not target_date.tzinfo:
                target_date = target_date.replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(400, "Invalid ISO format. Use YYYY-MM-DDTHH:MM:SSZ")
            
        return time_machine.get_posture_as_of(target_date)

    @app.post("/api/v1/retention/hold", tags=["Data Governance"])
    def apply_legal_hold(case_id: str, reason: str, objects: List[str]):
        hold = retention_mgr.create_hold(case_id, reason, objects)
        return asdict(hold)



def run_phase22_demo():
    print("\n" + "="*75)
    print(" PHASE 22: FORENSIC DATA LAKEHOUSE & HISTORICAL SEARCH")
    print("="*75 + "\n")

    lineage = LineageGraph()
    retention = RetentionManager()
    lake = ForensicDataLake(lineage, retention)
    search = SearchEngine(lake)
    time_machine = TimeMachineEngine(lake)

    # 1. Simulate Historical Data Ingestion (Bronze -> Silver -> Gold)
    print("[*] 1. Ingesting years of historical telemetry (Data Lineage tracking enabled)...")
    
    # 2024 Event
    raw1 = lake.ingest_bronze(b"mock_pcap_2024_data", "Sensor-01")
    lake.storage[raw1].timestamp = datetime(2024, 5, 1, tzinfo=timezone.utc)
    sess1 = lake.ingest_silver(raw1, {"asset": "MTA-07", "tls_version": "TLS 1.1", "ja4": "JA4-OLD"}, "SESSION")
    
    # 2025 Event
    raw2 = lake.ingest_bronze(b"mock_pcap_2025_data", "Sensor-01")
    lake.storage[raw2].timestamp = datetime(2025, 6, 15, tzinfo=timezone.utc)
    sess2 = lake.ingest_silver(raw2, {"asset": "MTA-07", "tls_version": "TLS 1.2", "ja4": "JA4-MID"}, "SESSION")
    
    # 2026 Event
    raw3 = lake.ingest_bronze(b"mock_pcap_2026_data", "Sensor-02")
    lake.storage[raw3].timestamp = datetime(2026, 9, 28, tzinfo=timezone.utc)
    sess3 = lake.ingest_silver(raw3, {"asset": "MTA-07", "tls_version": "TLS 1.3", "ja4": "JA4-NEW"}, "SESSION")
    
    # Gold Analytics Output based on Silver findings
    gold1 = lake.ingest_gold([sess1, sess2, sess3], {"insight": "TLS 1.1 eradicated on MTA-07", "asset": "MTA-07"}, "ASSET_POSTURE")
    
    print(f"    -> Total Objects in Lakehouse: {len(lake.storage)}")

    # 2. Data Lineage API
    print(f"\n[*] 2. Querying Data Provenance/Lineage for Gold Analytics Insight: {gold1}")
    trace = lineage.trace_lineage(gold1)
    for path in trace["trace"]:
        print(f"    -> {path}")

    # 3. Time Machine / Historical Posture
    print("\n[*] 3. Reconstructing Cryptographic Posture using 'Time Machine'...")
    past_posture = time_machine.get_posture_as_of(datetime(2024, 12, 31, tzinfo=timezone.utc))
    curr_posture = time_machine.get_posture_as_of(datetime(2026, 12, 31, tzinfo=timezone.utc))
    
    print("    [Posture at end of 2024]")
    print(f"      Deprecated TLS: {past_posture['metrics'].get('deprecated_pct', 0)}%")
    print(f"      Modern TLS 1.3: {past_posture['metrics'].get('tls1_3_pct', 0)}%")
    
    print("    [Posture at end of 2026]")
    print(f"      Deprecated TLS: {curr_posture['metrics'].get('deprecated_pct', 0)}%")
    print(f"      Modern TLS 1.3: {curr_posture['metrics'].get('tls1_3_pct', 0)}%")

    # 4. Enterprise Search (FQL)
    print("\n[*] 4. Executing Forensic Query Language (FQL) Search...")
    query = "FROM sessions WHERE asset = 'MTA-07'"
    results = search.execute_fql(query)
    print(f"    Query: '{query}'")
    for res in results:
        print(f"      -> Found {res['layer']} {res['object_id']}: {res['data'].get('tls_version')} (Date: {res['timestamp'][:10]})")

    # 5. Data Governance & Legal Hold
    print("\n[*] 5. Simulating Compliance & Legal Hold Restrictions...")
    print(f"    -> Applying Legal Hold on Case 'CASE-1022' for old PCAP: {raw1}")
    retention.create_hold("CASE-1022", "Pending litigation evidence preservation", [raw1])
    
    print("    -> Attempting to trigger automated lifecycle deletion of aged data...")
    lake.delete_object(raw2, "System_Auto_Prune") # Unprotected, should succeed
    lake.delete_object(raw1, "System_Auto_Prune") # Protected, should fail and log

    print("\n[✓] Phase 22 Execution Complete. The enterprise now has a persistent, queryable, governed forensic memory.")


def main():
    parser = argparse.ArgumentParser(description="Phase 22 - Forensic Data Lakehouse")
    parser.add_argument("command", choices=["serve", "demo"], help="Command to run", default="demo", nargs="?")
    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Phase 22 Lakehouse API on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("FastAPI not installed. Run 'demo' instead.")
    elif args.command == "demo":
        run_phase22_demo()

if __name__ == "__main__":
    main()