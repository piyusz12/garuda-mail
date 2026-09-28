import json
import time
import logging
import argparse
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field, asdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase10 - %(message)s")
logger = logging.getLogger("Continuous-Intelligence")

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. Phase 10 Web API disabled.")


# --- DATA MODELS ---

@dataclass
class Event:
    """A single normalized network event/session from Phase 7/8."""
    event_id: str
    timestamp: datetime
    event_type: str
    src_ip: str
    dst_ip: str
    protocol: str
    tls_version: Optional[str]
    ja4: Optional[str]
    certificate_sha256: Optional[str]
    asset_id: str
    risk_score: float
    risk_category: str
    ai_anomaly_score: float
    findings: List[str]

@dataclass
class Investigation:
    """A correlated chain of events forming an investigation."""
    investigation_id: str
    title: str
    status: str = "OPEN" # OPEN, INVESTIGATING, RESOLVED, CLOSED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    events: List[Event] = field(default_factory=list)
    entities_involved: Dict[str, Set[str]] = field(default_factory=lambda: {"ja4": set(), "assets": set()})
    risk_score: float = 0.0
    analyst_notes: str = ""

@dataclass
class EntityProfile:
    """Historical profile of an entity (JA4, Certificate, IP, Asset)."""
    entity_id: str
    entity_type: str
    first_seen: datetime
    last_seen: datetime
    session_count: int = 0
    anomalous_count: int = 0
    associated_assets: Set[str] = field(default_factory=set)
    historical_risk_median: float = 0.0

@dataclass
class AnalystFeedback:
    """Tracks human decisions to safely improve the AI baseline."""
    session_id: str
    disposition: str # CONFIRMED, BENIGN, FALSE_POSITIVE
    analyst_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    comment: str = ""


class EntityTracker:
    """Monitors the long-term behavior of JA4s, Certificates, and Assets."""
    
    def __init__(self):
        self.profiles: Dict[str, EntityProfile] = {}
        
    def _get_or_create(self, entity_id: str, entity_type: str, timestamp: datetime) -> EntityProfile:
        if entity_id not in self.profiles:
            self.profiles[entity_id] = EntityProfile(
                entity_id=entity_id,
                entity_type=entity_type,
                first_seen=timestamp,
                last_seen=timestamp
            )
            # Flag sudden population changes (e.g., New JA4)
            logger.info(f"NEW ENTITY DETECTED: {entity_type} [{entity_id}]")
        return self.profiles[entity_id]

    def ingest_event(self, event: Event):
        """Updates profiles based on a new network event."""
        entities_to_update = []
        if event.ja4:
            entities_to_update.append((event.ja4, "JA4"))
        if event.certificate_sha256:
            entities_to_update.append((event.certificate_sha256, "CERTIFICATE"))
        if event.asset_id:
            entities_to_update.append((event.asset_id, "ASSET"))
            
        for ent_id, ent_type in entities_to_update:
            profile = self._get_or_create(ent_id, ent_type, event.timestamp)
            profile.last_seen = event.timestamp
            profile.session_count += 1
            if event.asset_id:
                profile.associated_assets.add(event.asset_id)
            if event.ai_anomaly_score > 0.8:
                profile.anomalous_count += 1
                
            # Running median approximation for demonstration
            profile.historical_risk_median = (profile.historical_risk_median * 0.9) + (event.risk_score * 0.1)

    def get_profile(self, entity_id: str) -> Optional[Dict[str, Any]]:
        profile = self.profiles.get(entity_id)
        if not profile:
            return None
        
        # Serialize for API
        data = asdict(profile)
        data["associated_assets"] = list(profile.associated_assets)
        data["first_seen"] = profile.first_seen.isoformat()
        data["last_seen"] = profile.last_seen.isoformat()
        return data


class TemporalCorrelator:
    """Detects multi-stage attack patterns or operational failures across time windows."""
    
    def __init__(self, entity_tracker: EntityTracker):
        self.entity_tracker = entity_tracker
        self.event_buffer: List[Event] = []
        self.investigations: Dict[str, Investigation] = {}
        self.investigation_counter = 1

    def ingest_event(self, event: Event):
        self.event_buffer.append(event)
        self._purge_old_events(current_time=event.timestamp)
        self._evaluate_correlations(event)

    def _purge_old_events(self, current_time: datetime, max_window_minutes: int = 60):
        """Removes events older than the maximum correlation window."""
        cutoff = current_time - timedelta(minutes=max_window_minutes)
        self.event_buffer = [e for e in self.event_buffer if e.timestamp >= cutoff]

    def _evaluate_correlations(self, trigger_event: Event):
        """
        Evaluates heuristic correlation rules.
        Example Rule: New JA4 -> STARTTLS Failure -> High AI Anomaly within 30 minutes.
        """
        if trigger_event.ai_anomaly_score < 0.85:
            return # Only trigger on high-risk/anomaly anchors for this demo
            
        if not trigger_event.ja4:
            return

        # Look back in the buffer for related context
        related_events = [
            e for e in self.event_buffer 
            if e.ja4 == trigger_event.ja4 and e.event_id != trigger_event.event_id
        ]
        
        starttls_failures = any("STARTTLS_FAILURE" in e.findings for e in related_events)
        
        ja4_profile = self.entity_tracker.profiles.get(trigger_event.ja4)
        is_new_ja4 = False
        if ja4_profile:
            time_known = trigger_event.timestamp - ja4_profile.first_seen
            is_new_ja4 = time_known.total_seconds() < (24 * 3600) # Known for < 24 hrs
            
        if is_new_ja4 and starttls_failures:
            # We have a correlated behavioral chain!
            inv_id = f"INV-{datetime.now(timezone.utc).strftime('%Y%m')}-{self.investigation_counter:04d}"
            self.investigation_counter += 1
            
            chain = related_events + [trigger_event]
            
            inv = Investigation(
                investigation_id=inv_id,
                title=f"Suspicious Behavior Chain for New JA4 {trigger_event.ja4[:8]}",
                events=chain,
                risk_score=max(e.risk_score for e in chain)
            )
            inv.entities_involved["ja4"].add(trigger_event.ja4)
            for e in chain:
                inv.entities_involved["assets"].add(e.asset_id)
                
            self.investigations[inv_id] = inv
            logger.warning(f"TEMPORAL CORRELATION: Created {inv_id} -> {inv.title}")


class BaselineGuard:
    """
    Prevents model poisoning. Only Analyst-reviewed benign sessions 
    can enter the candidate baseline for retraining.
    """
    def __init__(self):
        self.feedback_db: List[AnalystFeedback] = []
        self.candidate_baseline: List[str] = [] # List of session IDs safe for training

    def register_feedback(self, feedback: AnalystFeedback):
        self.feedback_db.append(feedback)
        logger.info(f"Analyst {feedback.analyst_id} marked {feedback.session_id} as {feedback.disposition}")
        
        if feedback.disposition == "BENIGN":
            # Safe to use for unsupervised baseline learning
            self.candidate_baseline.append(feedback.session_id)
            logger.info(f"Session {feedback.session_id} promoted to candidate baseline.")
        elif feedback.disposition == "CONFIRMED":
            # Suspicious/Malicious. Exclude from baseline to prevent poisoning.
            if feedback.session_id in self.candidate_baseline:
                self.candidate_baseline.remove(feedback.session_id)
                logger.warning(f"Session {feedback.session_id} evicted from candidate baseline due to malicious feedback.")

class ModelLifecycleManager:
    """Manages Champion/Challenger model deployments based on the clean baseline."""
    def __init__(self, baseline_guard: BaselineGuard):
        self.baseline_guard = baseline_guard
        self.active_version = "ai-v1.0"
        
    def request_retrain(self) -> Dict[str, Any]:
        """Simulates training a challenger model on the new candidate baseline."""
        candidate_count = len(self.baseline_guard.candidate_baseline)
        if candidate_count < 100:
            return {"status": "REJECTED", "reason": f"Insufficient candidate data ({candidate_count}/100 needed)"}
            
        logger.info("Training Challenger Model...")
        # (Mock training process)
        time.sleep(1.0) 
        
        return {
            "status": "APPROVED",
            "message": "Challenger model trained and validated against Champion.",
            "champion_version": self.active_version,
            "challenger_version": f"ai-v1.{int(self.active_version.split('.')[-1]) + 1}",
            "validation_metrics": {
                "false_positive_improvement": "12%",
                "drift_stability": "STABLE"
            }
        }


if HAS_FASTAPI:
    app = FastAPI(
        title="Phase 10 - Continuous Intelligence API",
        description="Threat hunting, temporal correlation, and model lifecycle APIs.",
        version="1.0"
    )

    tracker = EntityTracker()
    correlator = TemporalCorrelator(tracker)
    guard = BaselineGuard()
    lifecycle = ModelLifecycleManager(guard)

    @app.post("/api/events/ingest", tags=["Ingestion"])
    def ingest_event(event_data: dict, background_tasks: BackgroundTasks):
        """Continuous pipeline ingestion endpoint."""
        try:
            event = Event(
                event_id=event_data["event_id"],
                timestamp=datetime.fromisoformat(event_data["timestamp"]),
                event_type=event_data["event_type"],
                src_ip=event_data["src_ip"],
                dst_ip=event_data["dst_ip"],
                protocol=event_data["protocol"],
                tls_version=event_data.get("tls_version"),
                ja4=event_data.get("ja4"),
                certificate_sha256=event_data.get("certificate_sha256"),
                asset_id=event_data["asset_id"],
                risk_score=event_data["risk_score"],
                risk_category=event_data["risk_category"],
                ai_anomaly_score=event_data["ai_anomaly_score"],
                findings=event_data.get("findings", [])
            )
            # Process asynchronously to ensure high throughput
            background_tasks.add_task(tracker.ingest_event, event)
            background_tasks.add_task(correlator.ingest_event, event)
            return {"status": "Accepted"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/entities/{entity_id}", tags=["Threat Hunting"])
    def get_entity_history(entity_id: str):
        profile = tracker.get_profile(entity_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Entity not found")
        return profile

    @app.get("/api/investigations", tags=["Operations"])
    def list_investigations():
        result = []
        for inv_id, inv in correlator.investigations.items():
            result.append({
                "id": inv_id,
                "title": inv.title,
                "status": inv.status,
                "risk_score": inv.risk_score,
                "entities_involved": {k: list(v) for k, v in inv.entities_involved.items()}
            })
        return {"investigations": result}

    @app.post("/api/feedback", tags=["Lifecycle"])
    def submit_feedback(session_id: str, disposition: str, analyst_id: str = "auto-api"):
        if disposition not in ["BENIGN", "CONFIRMED", "FALSE_POSITIVE"]:
            raise HTTPException(status_code=400, detail="Invalid disposition")
        
        fb = AnalystFeedback(session_id=session_id, disposition=disposition, analyst_id=analyst_id)
        guard.register_feedback(fb)
        return {"status": "Feedback Registered", "baseline_candidates": len(guard.candidate_baseline)}
        
    @app.post("/api/models/retrain", tags=["Lifecycle"])
    def request_model_retrain():
        return lifecycle.request_retrain()


def generate_mock_stream(tracker: EntityTracker, correlator: TemporalCorrelator):
    """Generates a synthetic stream of events to demonstrate temporal correlation."""
    print("\n--- INGESTING HISTORICAL EVENTS ---")
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)
    
    events = [
        # Normal background traffic
        Event("EV-1", base_time, "EMAIL", "10.0.0.1", "203.0.113.1", "SMTP", "TLS 1.3", "ja4_normal_01", None, "smtp-01", 10.0, "LOW", 0.1, []),
        Event("EV-2", base_time + timedelta(minutes=5), "EMAIL", "10.0.0.2", "203.0.113.1", "SMTP", "TLS 1.3", "ja4_normal_01", None, "smtp-01", 10.0, "LOW", 0.12, []),
        
        # Suspicious Sequence (New JA4 -> STARTTLS Failure -> High AI Anomaly)
        Event("EV-3", base_time + timedelta(minutes=45), "EMAIL", "192.168.1.100", "203.0.113.1", "SMTP", None, "ja4_suspicious_99", None, "smtp-01", 60.0, "MEDIUM", 0.4, ["STARTTLS_FAILURE"]),
        Event("EV-4", base_time + timedelta(minutes=46), "EMAIL", "192.168.1.100", "203.0.113.1", "SMTP", "TLS 1.1", "ja4_suspicious_99", "cert_hash_1", "smtp-01", 75.0, "HIGH", 0.6, ["TLS_DEPRECATED"]),
        Event("EV-5", base_time + timedelta(minutes=50), "EMAIL", "192.168.1.100", "203.0.113.1", "SMTP", "TLS 1.1", "ja4_suspicious_99", "cert_hash_1", "smtp-01", 95.0, "CRITICAL", 0.92, ["PLAINTEXT_AUTH", "AI_BEHAVIOR_ANOMALY"]),
    ]
    
    for ev in events:
        tracker.ingest_event(ev)
        correlator.ingest_event(ev)
        time.sleep(0.1) # Simulate ingestion delay
        
    print(f"\n--- INGESTION COMPLETE: {len(events)} events processed ---\n")

def main():
    parser = argparse.ArgumentParser(description="Phase 10 - Continuous Intelligence & Lifecycle")
    subparsers = parser.add_subparsers(dest="command", help="Available Commands")

    subparsers.add_parser("serve", help="Start the Continuous Intelligence API")
    subparsers.add_parser("demo", help="Run a live demonstration of Temporal Correlation and Baseline Guard")

    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Phase 10 Continuous Intelligence API on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("Error: FastAPI is not installed.")

    elif args.command == "demo":
        tracker = EntityTracker()
        correlator = TemporalCorrelator(tracker)
        guard = BaselineGuard()
        lifecycle = ModelLifecycleManager(guard)
        
        # 1. Generate Event Stream
        generate_mock_stream(tracker, correlator)
        
        # 2. Show Generated Investigations (Temporal Correlation)
        print("=== ACTIVE INVESTIGATIONS ===")
        for inv_id, inv in correlator.investigations.items():
            print(f"[{inv_id}] {inv.title}")
            print(f"  Status: {inv.status}")
            print(f"  Max Risk: {inv.risk_score}")
            print(f"  Entities: {inv.entities_involved}")
            print(f"  Event Chain Count: {len(inv.events)}")
            print("-" * 30)

        # 3. Demonstrate Analyst Feedback (Baseline Guard)
        print("\n=== ANALYST FEEDBACK LOOP ===")
        print("Simulating Analyst Review of Session EV-5 (Malicious):")
        guard.register_feedback(AnalystFeedback("EV-5", "CONFIRMED", "Analyst-A"))
        
        print("\nSimulating Analyst Review of Session EV-1 (False Positive/Benign):")
        guard.register_feedback(AnalystFeedback("EV-1", "BENIGN", "Analyst-A"))
        
        print(f"\nCandidate Baseline Size: {len(guard.candidate_baseline)}")
        
        # 4. Model Lifecycle
        print("\n=== MODEL LIFECYCLE EVALUATION ===")
        print("Requesting Retrain (Will reject due to low volume)...")
        print(json.dumps(lifecycle.request_retrain(), indent=2))
        
        print("\nInjecting dummy baseline data to force training...")
        guard.candidate_baseline.extend([f"DUMMY-{i}" for i in range(150)])
        print(json.dumps(lifecycle.request_retrain(), indent=2))
        
    else:
        parser.print_help()

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        sys.argv.append("demo")
    main()