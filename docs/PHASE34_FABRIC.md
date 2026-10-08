# Phase 34 Distributed AI Fabric Foundation

This slice establishes the control-plane boundary for distributed workloads without claiming that inference is already dispatched to physical workers.

## Fabric APIs

| Endpoint | Purpose | Access |
| --- | --- | --- |
| `GET /api/fabric/nodes` | View registered node capabilities and health | Authenticated |
| `PATCH /api/fabric/nodes` | Apply a node heartbeat | Administrator |
| `POST /api/fabric/schedule` | Evaluate policy and select an eligible node | Authenticated |

## Scheduling decisions

Scheduling filters nodes in this order:

1. Healthy status and trusted identity state
2. Required capability
3. Requested model availability
4. Data-zone locality
5. Available VRAM
6. Explainable score using trust, free VRAM, queue pressure, and priority

The scheduler returns the selected node and rejection/selection reasons. It does not execute work yet. That boundary is intentional: node enrollment, signed heartbeats, durable jobs, worker dispatch, and failover belong to later Phase 34 slices.

## Demo nodes

The development registry contains synthetic nodes `NODE-001` and `NODE-002` so the control-plane behavior can be demonstrated without claiming hardware that is not connected.