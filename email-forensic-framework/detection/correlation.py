"""
Phase 23 - Multi-Stage Temporal Correlation and Deduplication Engine.
Detects multi-stage attack patterns (A -> B -> C), partial sequences, and clusters alerts.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
import uuid

@dataclass
class TemporalStage:
    stage_name: str
    event_type: str
    match_criteria: Dict[str, Any]
    max_window_seconds: int = 86400  # default 24h

@dataclass
class SequenceDefinition:
    sequence_id: str
    name: str
    stages: List[TemporalStage]
    min_stages_for_partial: int = 2

@dataclass
class SequenceMatch:
    sequence_id: str
    asset_id: str
    is_complete: bool
    matched_stages: List[str]
    missing_stages: List[str]
    start_time: datetime
    end_time: datetime
    evidence_ids: List[str]


class CorrelationEngine:
    """Manages stateful sequence tracking and alert deduplication."""

    def __init__(self):
        # Asset -> List of chronological events: {"event_id", "type", "timestamp", "data"}
        self.asset_timeline: Dict[str, List[Dict[str, Any]]] = {}
        # Active sequences
        self.sequences: Dict[str, SequenceDefinition] = {}
        # Deduplication cache: key -> cluster details
        self.dedup_clusters: Dict[str, Dict[str, Any]] = {}

    def register_sequence(self, seq: SequenceDefinition):
        self.sequences[seq.sequence_id] = seq

    def ingest_event(self, asset_id: str, event_type: str, data: Dict[str, Any], event_id: Optional[str] = None, timestamp: Optional[datetime] = None) -> List[SequenceMatch]:
        """Ingests an event, updates asset timeline, and evaluates active sequences."""
        event_id = event_id or f"EVT-{uuid.uuid4().hex[:8].upper()}"
        ts = timestamp or datetime.now(timezone.utc)

        if asset_id not in self.asset_timeline:
            self.asset_timeline[asset_id] = []
        
        event_entry = {
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": ts,
            "data": data
        }
        self.asset_timeline[asset_id].append(event_entry)
        # Keep sorted by timestamp
        self.asset_timeline[asset_id].sort(key=lambda x: x["timestamp"])

        return self._evaluate_sequences_for_asset(asset_id)

    def _evaluate_sequences_for_asset(self, asset_id: str) -> List[SequenceMatch]:
        history = self.asset_timeline.get(asset_id, [])
        matches = []

        for seq in self.sequences.values():
            stage_idx = 0
            matched_stages = []
            matched_evidence = []
            last_ts = None
            first_ts = None

            for evt in history:
                if stage_idx >= len(seq.stages):
                    break
                curr_stage = seq.stages[stage_idx]

                if evt["event_type"] == curr_stage.event_type:
                    # Check match criteria
                    data = evt["data"]
                    cond_met = True
                    for k, v in curr_stage.match_criteria.items():
                        if str(data.get(k, "")).lower() != str(v).lower():
                            cond_met = False
                            break
                    
                    if cond_met:
                        if last_ts is not None:
                            diff = (evt["timestamp"] - last_ts).total_seconds()
                            if diff > curr_stage.max_window_seconds:
                                # Window exceeded, reset sequence tracking from this event
                                matched_stages = [curr_stage.stage_name]
                                matched_evidence = [evt["event_id"]]
                                first_ts = evt["timestamp"]
                                last_ts = evt["timestamp"]
                                stage_idx = 1
                                continue

                        if not matched_stages:
                            first_ts = evt["timestamp"]
                        matched_stages.append(curr_stage.stage_name)
                        matched_evidence.append(evt["event_id"])
                        last_ts = evt["timestamp"]
                        stage_idx += 1

            all_stage_names = [s.stage_name for s in seq.stages]
            missing = [s for s in all_stage_names if s not in matched_stages]
            is_complete = len(matched_stages) == len(seq.stages)

            if is_complete or len(matched_stages) >= seq.min_stages_for_partial:
                matches.append(SequenceMatch(
                    sequence_id=seq.sequence_id,
                    asset_id=asset_id,
                    is_complete=is_complete,
                    matched_stages=matched_stages,
                    missing_stages=missing,
                    start_time=first_ts or datetime.now(timezone.utc),
                    end_time=last_ts or datetime.now(timezone.utc),
                    evidence_ids=matched_evidence
                ))

        return matches

    def cluster_and_deduplicate(self, detection_id: str, asset_id: str, event_id: str, window_minutes: int = 60) -> Tuple[bool, str, int]:
        """
        Deduplicates repeated detections into single finding clusters.
        Returns: (is_new_cluster, cluster_id, total_event_count)
        """
        cluster_key = f"{detection_id}:{asset_id}"
        now = datetime.now(timezone.utc)

        if cluster_key in self.dedup_clusters:
            cluster = self.dedup_clusters[cluster_key]
            # Check window
            elapsed = (now - cluster["last_seen"]).total_seconds() / 60.0
            if elapsed <= window_minutes:
                cluster["count"] += 1
                cluster["last_seen"] = now
                cluster["events"].append(event_id)
                return False, cluster["cluster_id"], cluster["count"]

        # New cluster
        cluster_id = f"FND-CLUSTER-{uuid.uuid4().hex[:6].upper()}"
        self.dedup_clusters[cluster_key] = {
            "cluster_id": cluster_id,
            "detection_id": detection_id,
            "asset_id": asset_id,
            "first_seen": now,
            "last_seen": now,
            "count": 1,
            "events": [event_id]
        }
        return True, cluster_id, 1
