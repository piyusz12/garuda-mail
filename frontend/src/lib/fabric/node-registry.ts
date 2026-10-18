export type NodeStatus = 'healthy' | 'degraded' | 'unavailable' | 'recovering' | 'quarantined';
export type NodeTrust = 'trusted' | 'limited' | 'untrusted' | 'quarantined';
export type NodeRole = 'WORKER_GPU' | 'WORKER_CPU' | 'STORAGE_RAG' | 'GATEWAY' | 'CONTROL_PLANE';
export type NetworkZone = 'RESTRICTED_AI' | 'INTERNAL_AI' | 'GENERAL_AI' | 'STORAGE_NET' | 'MANAGEMENT_NET';

export interface FabricNode {
  nodeId: string;
  hostname: string;
  ipAddress: string;
  status: NodeStatus;
  role: NodeRole;
  trust: NodeTrust;
  zone: NetworkZone;
  capabilities: string[];
  models: string[];
  gpuName: string;
  vramTotalGb: number;
  vramUsedGb: number;
  ramTotalGb: number;
  ramUsedGb: number;
  cpuCores: number;
  cpuUsagePct: number;
  activeJobs: number;
  temperatureC: number;
  diskUsedPct: number;
  lastSeen: string;
  softwareVersion: string;
  securityState: string;
}

export interface NodeHeartbeat {
  nodeId: string;
  status?: NodeStatus;
  cpuUsagePct?: number;
  ramUsedGb?: number;
  vramUsedGb?: number;
  activeJobs?: number;
  temperatureC?: number;
  capabilities?: string[];
  models?: string[];
  lastSeen?: string;
}

export interface EnrollmentRequest {
  requestId: string;
  hostname: string;
  ipAddress: string;
  role: NodeRole;
  advertisedGpu: string;
  advertisedVramGb: number;
  advertisedRamGb: number;
  advertisedCapabilities: string[];
  requestedZone: NetworkZone;
  requestedAt: string;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED';
  decisionReason?: string;
}

declare global {
  var __garudaFabricNodes: Map<string, FabricNode> | undefined;
  var __garudaFabricEnrollments: Map<string, EnrollmentRequest> | undefined;
}

const nodes = global.__garudaFabricNodes || (global.__garudaFabricNodes = new Map());
const enrollments = global.__garudaFabricEnrollments || (global.__garudaFabricEnrollments = new Map());

const seedNodes: FabricNode[] = [
  {
    nodeId: 'NODE-001',
    hostname: 'garuda-rtx4060-workstation',
    ipAddress: '192.168.1.101',
    status: 'healthy',
    role: 'WORKER_GPU',
    trust: 'trusted',
    zone: 'RESTRICTED_AI',
    capabilities: ['chat', 'coding', 'embeddings', 'reranking', 'llm_inference', 'rag'],
    models: ['local-approved', 'qwen-local', 'bge-embeddings'],
    gpuName: 'NVIDIA GeForce RTX 4060 Laptop GPU',
    vramTotalGb: 8.0,
    vramUsedGb: 3.2,
    ramTotalGb: 16.0,
    ramUsedGb: 7.8,
    cpuCores: 16,
    cpuUsagePct: 24.5,
    activeJobs: 0,
    temperatureC: 52.0,
    diskUsedPct: 42.0,
    lastSeen: new Date().toISOString(),
    softwareVersion: '34.0.0',
    securityState: 'COMPLIANT_SOVEREIGN',
  },
  {
    nodeId: 'NODE-002',
    hostname: 'garuda-ai-server-02',
    ipAddress: '192.168.1.102',
    status: 'healthy',
    role: 'WORKER_GPU',
    trust: 'trusted',
    zone: 'INTERNAL_AI',
    capabilities: ['chat', 'llm_inference', 'vision', 'coding', 'embeddings', 'image_processing', 'video_analysis'],
    models: ['qwen-coder-7b', 'qwen-vl-vision', 'qwen-local'],
    gpuName: 'NVIDIA RTX 4090',
    vramTotalGb: 24.0,
    vramUsedGb: 8.5,
    ramTotalGb: 64.0,
    ramUsedGb: 22.4,
    cpuCores: 32,
    cpuUsagePct: 38.0,
    activeJobs: 0,
    temperatureC: 58.0,
    diskUsedPct: 29.0,
    lastSeen: new Date().toISOString(),
    softwareVersion: '34.0.0',
    securityState: 'COMPLIANT_SOVEREIGN',
  },
  {
    nodeId: 'NODE-003',
    hostname: 'garuda-storage-worker',
    ipAddress: '192.168.1.103',
    status: 'healthy',
    role: 'STORAGE_RAG',
    trust: 'trusted',
    zone: 'STORAGE_NET',
    capabilities: ['vector_store', 'document_processing', 'embeddings', 'database'],
    models: ['bge-embeddings'],
    gpuName: 'CPU Cluster (Dual Xeon)',
    vramTotalGb: 0.0,
    vramUsedGb: 0.0,
    ramTotalGb: 32.0,
    ramUsedGb: 11.2,
    cpuCores: 16,
    cpuUsagePct: 18.5,
    activeJobs: 0,
    temperatureC: 41.0,
    diskUsedPct: 48.0,
    lastSeen: new Date().toISOString(),
    softwareVersion: '34.0.0',
    securityState: 'COMPLIANT_SOVEREIGN',
  },
  {
    nodeId: 'NODE-004-QUARANTINED',
    hostname: 'untrusted-rogue-node',
    ipAddress: '192.168.1.250',
    status: 'quarantined',
    role: 'WORKER_GPU',
    trust: 'quarantined',
    zone: 'GENERAL_AI',
    capabilities: ['chat'],
    models: [],
    gpuName: 'Generic Workstation GPU',
    vramTotalGb: 8.0,
    vramUsedGb: 8.0,
    ramTotalGb: 16.0,
    ramUsedGb: 15.0,
    cpuCores: 8,
    cpuUsagePct: 95.0,
    activeJobs: 0,
    temperatureC: 85.0,
    diskUsedPct: 92.0,
    lastSeen: new Date().toISOString(),
    softwareVersion: '33.1.0',
    securityState: 'QUARANTINED: Suspicious unapproved container execution',
  },
];

for (const node of seedNodes) {
  if (!nodes.has(node.nodeId)) nodes.set(node.nodeId, node);
}

// Seed a sample enrollment request
if (enrollments.size === 0) {
  enrollments.set('ENROLL-LAB-05', {
    requestId: 'ENROLL-LAB-05',
    hostname: 'lab-workstation-rtx3090',
    ipAddress: '192.168.1.105',
    role: 'WORKER_GPU',
    advertisedGpu: 'NVIDIA RTX 3090',
    advertisedVramGb: 24.0,
    advertisedRamGb: 64.0,
    advertisedCapabilities: ['vision', 'llm_inference', 'embeddings'],
    requestedZone: 'INTERNAL_AI',
    requestedAt: new Date(Date.now() - 3600000).toISOString(),
    status: 'PENDING_APPROVAL',
  });
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

export function quarantineNode(nodeId: string, reason: string): FabricNode | null {
  const node = nodes.get(nodeId);
  if (!node) return null;
  node.status = 'quarantined';
  node.trust = 'quarantined';
  node.securityState = `QUARANTINED: ${reason}`;
  nodes.set(node.nodeId, node);
  return node;
}

export function applyHeartbeat(heartbeat: NodeHeartbeat): FabricNode | null {
  const node = nodes.get(heartbeat.nodeId);
  if (!node) return null;

  const updated: FabricNode = {
    ...node,
    ...(heartbeat.status ? { status: heartbeat.status } : {}),
    ...(heartbeat.cpuUsagePct !== undefined ? { cpuUsagePct: heartbeat.cpuUsagePct } : {}),
    ...(heartbeat.ramUsedGb !== undefined ? { ramUsedGb: heartbeat.ramUsedGb } : {}),
    ...(heartbeat.vramUsedGb !== undefined ? { vramUsedGb: heartbeat.vramUsedGb } : {}),
    ...(heartbeat.activeJobs !== undefined ? { activeJobs: heartbeat.activeJobs } : {}),
    ...(heartbeat.temperatureC !== undefined ? { temperatureC: heartbeat.temperatureC } : {}),
    ...(heartbeat.capabilities ? { capabilities: heartbeat.capabilities } : {}),
    ...(heartbeat.models ? { models: heartbeat.models } : {}),
    lastSeen: heartbeat.lastSeen || new Date().toISOString(),
  };

  // Detect OOM / VRAM saturation
  if (updated.vramTotalGb > 0 && updated.vramUsedGb >= updated.vramTotalGb) {
    updated.status = 'degraded';
    updated.securityState = 'WARNING: GPU VRAM Saturation';
  }

  nodes.set(updated.nodeId, updated);
  return updated;
}

export function listEnrollmentRequests(): EnrollmentRequest[] {
  return Array.from(enrollments.values()).sort(
    (a, b) => new Date(b.requestedAt).getTime() - new Date(a.requestedAt).getTime()
  );
}

export function submitEnrollmentRequest(req: Omit<EnrollmentRequest, 'requestId' | 'requestedAt' | 'status'>): EnrollmentRequest {
  const requestId = `ENROLL-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
  const fullReq: EnrollmentRequest = {
    ...req,
    requestId,
    requestedAt: new Date().toISOString(),
    status: 'PENDING_APPROVAL',
  };
  enrollments.set(requestId, fullReq);
  return fullReq;
}

export function approveEnrollment(requestId: string, adminId = 'admin'): FabricNode | null {
  const req = enrollments.get(requestId);
  if (!req || req.status !== 'PENDING_APPROVAL') return null;

  req.status = 'APPROVED';
  req.decisionReason = `Approved by administrator ${adminId}`;

  const newNodeId = `GARUDA-NODE-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;
  const newNode: FabricNode = {
    nodeId: newNodeId,
    hostname: req.hostname,
    ipAddress: req.ipAddress,
    status: 'healthy',
    role: req.role,
    trust: 'trusted',
    zone: req.requestedZone,
    capabilities: req.advertisedCapabilities,
    models: [],
    gpuName: req.advertisedGpu,
    vramTotalGb: req.advertisedVramGb,
    vramUsedGb: 0.0,
    ramTotalGb: req.advertisedRamGb,
    ramUsedGb: 2.0,
    cpuCores: 16,
    cpuUsagePct: 8.0,
    activeJobs: 0,
    temperatureC: 45.0,
    diskUsedPct: 20.0,
    lastSeen: new Date().toISOString(),
    softwareVersion: '34.0.0',
    securityState: 'ENROLLED_SOVEREIGN',
  };

  nodes.set(newNodeId, newNode);
  return newNode;
}

export function rejectEnrollment(requestId: string, reason: string): EnrollmentRequest | null {
  const req = enrollments.get(requestId);
  if (!req) return null;
  req.status = 'REJECTED';
  req.decisionReason = reason;
  return req;
}