import json
import uuid
import time
import asyncio
import logging
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Callable

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase19 - %(message)s")
logger = logging.getLogger("Live-Sensor-Fabric")

try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. Real-time WebSockets and API disabled.")


@dataclass
class StreamEvent:
    """The universal event envelope used across the Kafka-like streaming broker."""
    event_id: str
    event_type: str # e.g., FLOW_CREATED, STARTTLS_FAILURE, ANOMALY_DETECTED
    timestamp: str
    tenant_id: str
    sensor_id: str
    flow_id: str
    payload: Dict[str, Any]
    schema_version: str = "1.0"
    ingest_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class SensorHealth:
    packets_per_second: int = 0
    packet_drop_rate: float = 0.0
    buffer_usage: float = 0.0
    publish_rate: int = 0
    lag_ms: int = 0

@dataclass
class PassiveSensorNode:
    """Represents a managed identity in the Sensor Registry."""
    sensor_id: str
    name: str
    location: str
    status: str = "ONLINE"
    capture_profile: str = "email-crypto"
    health: SensorHealth = field(default_factory=SensorHealth)
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EventBroker:
    """
    In-memory asynchronous event broker.
    Simulates partitioned topics and consumer groups.
    """
    def __init__(self):
        self.topics: Dict[str, asyncio.Queue] = {
            "pcap.packet": asyncio.Queue(),
            "flow.events": asyncio.Queue(),
            "tls.events": asyncio.Queue(),
            "risk.events": asyncio.Queue(),
            "incident.events": asyncio.Queue(),
            "sensor.control": asyncio.Queue()
        }
        self.subscribers: Dict[str, List[Callable]] = {topic: [] for topic in self.topics}
        self._running = True

    async def publish(self, topic: str, event: StreamEvent):
        """Publishes an event to a specific topic."""
        if topic in self.topics:
            await self.topics[topic].put(event)

    def subscribe(self, topic: str, callback: Callable):
        """Registers a worker function to consume a topic."""
        if topic in self.subscribers:
            self.subscribers[topic].append(callback)

    async def _broker_loop(self, topic: str):
        """Internal loop distributing messages from queues to subscribers."""
        while self._running:
            try:
                event: StreamEvent = await asyncio.wait_for(self.topics[topic].get(), timeout=0.5)
                for callback in self.subscribers[topic]:
                    # Process concurrently without blocking the queue
                    asyncio.create_task(callback(event))
                self.topics[topic].task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"[Broker] Error routing {topic}: {e}")

    async def start(self):
        self._running = True
        for topic in self.topics:
            asyncio.create_task(self._broker_loop(topic))
            
    def stop(self):
        self._running = False


class EdgeSensorClient:
    """
    Simulates the lightweight edge capture agent deployed via SPAN/TAP.
    Captures traffic, extracts lightweight metadata, buffers, and streams.
    """
    def __init__(self, sensor_id: str, broker: EventBroker):
        self.sensor_id = sensor_id
        self.broker = broker
        self.local_buffer: List[StreamEvent] = []
        self.max_buffer = 10000

    def _create_event(self, event_type: str, flow_id: str, payload: Dict[str, Any]) -> StreamEvent:
        return StreamEvent(
            event_id=f"EV-{uuid.uuid4().hex[:8].upper()}",
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tenant_id="enterprise-hq",
            sensor_id=self.sensor_id,
            flow_id=flow_id,
            payload=payload
        )

    async def sniff_traffic(self):
        """Mocks live traffic capture and flow state machine updates."""
        logger.info(f"[{self.sensor_id}] Listening on physical interface (eth0)...")
        
        flow_id = f"FLOW-{uuid.uuid4().hex[:6].upper()}"
        
        # 1. Flow Created (TCP SYN)
        await asyncio.sleep(0.1)
        ev1 = self._create_event("FLOW_CREATED", flow_id, {"src": "10.0.0.45", "dst": "203.0.113.10", "proto": "TCP"})
        await self.broker.publish("flow.events", ev1)
        
        # 2. SMTP Protocol Detected incrementally
        await asyncio.sleep(0.1)
        ev2 = self._create_event("PROTOCOL_CONFIRMED", flow_id, {"protocol": "SMTP"})
        await self.broker.publish("flow.events", ev2)
        
        # 3. STARTTLS Requested & Failed
        await asyncio.sleep(0.05)
        ev3 = self._create_event("STARTTLS_FAILURE", flow_id, {"reason": "NEGOTIATION_REJECTED"})
        await self.broker.publish("tls.events", ev3)
        
        # 4. Fallback to Plaintext & JA4 generation
        await asyncio.sleep(0.05)
        ev4 = self._create_event("JA4_OBSERVED", flow_id, {"ja4": "t11d150800_002f_a54b321"})
        await self.broker.publish("tls.events", ev4)

    async def preserve_evidence(self, flow_id: str):
        """Triggered retroactively when the central incident engine flags a flow."""
        logger.warning(f"[{self.sensor_id}] 🛑 ROTATING & PRESERVING PCAP SEGMENT FOR {flow_id}")
        await asyncio.sleep(0.2) # Simulate writing from ring buffer to disk
        logger.warning(f"[{self.sensor_id}] Evidence locked: /var/sensor/evidence/{flow_id}.pcap (SHA256: 8f2a...)")


class StreamingWorkers:
    """
    Sub-second event processors. They listen to specific topics,
    update rolling state, and emit enriched downstream events.
    """
    def __init__(self, broker: EventBroker, sensor: EdgeSensorClient):
        self.broker = broker
        self.sensor = sensor # Ref to sensor for evidence callbacks
        
        # Register stream processors
        self.broker.subscribe("tls.events", self.process_tls_events)
        self.broker.subscribe("risk.events", self.process_risk_events)

    async def process_tls_events(self, event: StreamEvent):
        """Worker combining TLS rules and AI Anomaly inference."""
        latency = (datetime.now(timezone.utc) - datetime.fromisoformat(event.timestamp)).microseconds / 1000
        logger.debug(f"[TLS Worker] Processing {event.event_type} ({latency}ms latency)")
        
        if event.event_type == "STARTTLS_FAILURE":
            # Real-time deterministic rule
            risk_payload = {
                "rule_id": "STARTTLS-FAIL-001",
                "severity": "HIGH",
                "evidence": "STARTTLS command explicitly rejected."
            }
            risk_ev = StreamEvent(
                event_id=f"EV-{uuid.uuid4().hex[:8].upper()}",
                event_type="FINDING_GENERATED",
                timestamp=datetime.now(timezone.utc).isoformat(),
                tenant_id=event.tenant_id,
                sensor_id=event.sensor_id,
                flow_id=event.flow_id,
                payload=risk_payload
            )
            await self.broker.publish("risk.events", risk_ev)
            
        elif event.event_type == "JA4_OBSERVED":
            # Simulate real-time streaming AI behavioral check
            ja4 = event.payload.get("ja4")
            if ja4 == "t11d150800_002f_a54b321":
                anomaly_ev = StreamEvent(
                    event_id=f"EV-{uuid.uuid4().hex[:8].upper()}",
                    event_type="AI_ANOMALY_DETECTED",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tenant_id=event.tenant_id,
                    sensor_id=event.sensor_id,
                    flow_id=event.flow_id,
                    payload={"score": 0.88, "top_feature": "JA4 Context Variance"}
                )
                await self.broker.publish("risk.events", anomaly_ev)


    async def process_risk_events(self, event: StreamEvent):
        """Correlates multiple findings on a single flow into an actionable Incident."""
        logger.info(f"[Risk Engine] Received {event.event_type} on {event.flow_id}")
        
        # A simple stateful correlation check (in reality, backed by Redis)
        if event.event_type == "AI_ANOMALY_DETECTED":
            # We treat high-scoring AI anomalies coupled with rules as immediate incidents
            logger.error(f"[Incident Engine] 🚨 REAL-TIME INCIDENT CREATED FOR {event.flow_id}! 🚨")
            
            # Send an immediate command back to the edge sensor to lock the PCAP buffer
            await self.sensor.preserve_evidence(event.flow_id)


if HAS_FASTAPI:
    app = FastAPI(title="Phase 19 - Live Sensor Fabric", version="19.0.0")
    
    # Global singletons for API access
    broker = EventBroker()
    sensor = EdgeSensorClient("SENSOR-HQ-01", broker)
    workers = StreamingWorkers(broker, sensor)
    
    dashboard_clients: List[WebSocket] = []

    async def broadcast_to_dashboard(event: StreamEvent):
        """Sends live events to any connected SOC WebSocket clients."""
        for client in dashboard_clients:
            try:
                await client.send_json(asdict(event))
            except Exception:
                dashboard_clients.remove(client)

    @app.on_event("startup")
    async def startup_event():
        await broker.start()
        # Bridge broker to websockets
        broker.subscribe("flow.events", broadcast_to_dashboard)
        broker.subscribe("tls.events", broadcast_to_dashboard)
        broker.subscribe("risk.events", broadcast_to_dashboard)

    @app.websocket("/ws/dashboard")
    async def websocket_dashboard(websocket: WebSocket):
        await websocket.accept()
        dashboard_clients.append(websocket)
        try:
            while True:
                await websocket.receive_text() # Keep connection alive
        except WebSocketDisconnect:
            dashboard_clients.remove(websocket)

    @app.get("/api/v1/sensors")
    def get_sensors():
        return [asdict(PassiveSensorNode(sensor.sensor_id, "Core-Router-Tap", "US-East"))]


async def run_phase19_demo():
    print("\n" + "="*70)
    print(" PHASE 19: REAL-TIME PASSIVE SENSOR FABRIC & STREAMING FORENSICS")
    print("="*70 + "\n")
    
    # 1. Initialize Fabric
    broker = EventBroker()
    await broker.start()
    
    sensor = EdgeSensorClient("SENSOR-HQ-01", broker)
    workers = StreamingWorkers(broker, sensor)
    
    print("[*] Streaming Fabric Initialized. Broker running, Workers listening.\n")
    print("--- LIVE TRAFFIC FEED ---")
    
    # 2. Simulate continuous traffic sniffing at the edge
    capture_task = asyncio.create_task(sensor.sniff_traffic())
    
    # Wait for the flow to process through the entire distributed pipeline
    await capture_task
    await asyncio.sleep(1.0) # Allow async events to propagate through queues
    
    broker.stop()
    print("\n[✓] Phase 19 Complete. Platform successfully transitioned from PCAP files to Sub-Second Streaming.")


def main():
    parser = argparse.ArgumentParser(description="Phase 19 - Real-Time Sensor Fabric")
    parser.add_argument("command", choices=["serve", "demo"], help="Command to run", default="demo", nargs="?")
    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Phase 19 Streaming Control Plane on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("FastAPI not installed. Run 'demo' instead.")
    elif args.command == "demo":
        asyncio.run(run_phase19_demo())

if __name__ == "__main__":
    main()