export type NodeStatus = 'healthy' | 'degraded' | 'unavailable' | 'quarantined';
export type NodeTrust = 'trusted' | 'limited' | 'untrusted' | 'quarantined';

export interface FabricNode {
  nodeId: string;
  hostname: string;
  status: NodeStatus;
  trust: NodeTrust;
  zone: string;
  capabilities: string[];
  models: string[];
  vramTotalGb: number;
  vramUsedGb: number;
  activeJobs: number;
  lastSeen: string;
  softwareVersion: string;
}

export interface NodeHeartbeat {
  nodeId: string;
  status?: NodeStatus;
  vramUsedGb?: number;
  activeJobs?: number;
  capabilities?: string[];
  models?: string[];
  lastSeen?: string;
}

declare global {
  // eslint-disable-next-line no-var
  var __garudaFabricNodes: Map<string, FabricNode> | undefined;
}

const nodes = global.__garudaFabricNodes || (global.__garudaFabricNodes = new Map());

const seedNodes: FabricNode[] = [
  {
    nodeId: 'NODE-001',
    hostname: 'garuda-workstation',
    status: 'healthy',
    trust: 'trusted',
    zone: 'RESTRICTED_AI',
    capabilities: ['chat', 'rag', 'embeddings', 'reranking'],
    models: ['local-approved', 'qwen-local'],
    vramTotalGb: 8,
    vramUsedGb: 3.2,
    activeJobs: 0,
    lastSeen: new Date().toISOString(),
    softwareVersion: '34.0.0',
  },
  {
    nodeId: 'NODE-002',
    hostname: 'garuda-cpu-worker',
    status: 'healthy',
    trust: 'trusted',
    zone: 'INTERNAL_AI',
    capabilities: ['document-processing', 'embeddings'],
    models: ['embedding-local'],
    vramTotalGb: 0,
    vramUsedGb: 0,
    activeJobs: 0,
    lastSeen: new Date().toISOString(),
    softwareVersion: '34.0.0',
  },
];

for (const node of seedNodes) {
  if (!nodes.has(node.nodeId)) nodes.set(node.nodeId, node);
}

export function listNodes(): FabricNode[] {
  return Array.from(nodes.values()).sort((left, right) => left.nodeId.localeCompare(right.nodeId));
}

export function getNode(nodeId: string): FabricNode | undefined {
  return nodes.get(nodeId);
}

export function upsertNode(node: FabricNode): FabricNode {
  nodes.set(node.nodeId, node);
  return node;
}

export function applyHeartbeat(heartbeat: NodeHeartbeat): FabricNode | null {
  const node = nodes.get(heartbeat.nodeId);
  if (!node) return null;

  const updated = {
    ...node,
    ...(heartbeat.status ? { status: heartbeat.status } : {}),
    ...(heartbeat.vramUsedGb !== undefined ? { vramUsedGb: heartbeat.vramUsedGb } : {}),
    ...(heartbeat.activeJobs !== undefined ? { activeJobs: heartbeat.activeJobs } : {}),
    ...(heartbeat.capabilities ? { capabilities: heartbeat.capabilities } : {}),
    ...(heartbeat.models ? { models: heartbeat.models } : {}),
    lastSeen: heartbeat.lastSeen || new Date().toISOString(),
  };
  nodes.set(updated.nodeId, updated);
  return updated;
}