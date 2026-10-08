import type { DataClassification } from '@/lib/governance/policy-engine';
import { listNodes, type FabricNode } from '@/lib/fabric/node-registry';

export interface WorkloadRequest {
  capability: string;
  model?: string;
  minVramGb?: number;
  dataClassification?: DataClassification;
  allowedZones?: string[];
  priority?: 'critical' | 'high' | 'normal' | 'low' | 'background';
}

export interface NodeCandidate {
  nodeId: string;
  score: number;
  reasons: string[];
}

export interface ScheduleDecision {
  selectedNode: FabricNode | null;
  candidates: NodeCandidate[];
  reason: string;
}

const TRUST_SCORE = { trusted: 100, limited: 50, untrusted: 0, quarantined: -100 } as const;
const PRIORITY_SCORE = { critical: 20, high: 10, normal: 0, low: -5, background: -10 } as const;

export function scheduleWorkload(request: WorkloadRequest, availableNodes = listNodes()): ScheduleDecision {
  const candidates = availableNodes
    .filter(node => node.status === 'healthy' && node.trust === 'trusted')
    .filter(node => node.capabilities.includes(request.capability))
    .filter(node => !request.model || node.models.includes(request.model))
    .filter(node => !request.allowedZones || request.allowedZones.includes(node.zone))
    .filter(node => (node.vramTotalGb - node.vramUsedGb) >= (request.minVramGb || 0))
    .map(node => {
      const freeVram = node.vramTotalGb - node.vramUsedGb;
      const reasons = [
        'Trusted healthy node',
        `Capability ${request.capability} available`,
        request.model ? `Model ${request.model} available` : 'Model requirement not specified',
        request.allowedZones ? `Zone ${node.zone} allowed` : 'No zone restriction',
        `${freeVram.toFixed(1)} GB VRAM available`,
      ];
      const score = TRUST_SCORE[node.trust] + freeVram * 10 - node.activeJobs * 5 + PRIORITY_SCORE[request.priority || 'normal'];
      return { nodeId: node.nodeId, score, reasons };
    })
    .sort((left, right) => right.score - left.score);

  if (!candidates.length) {
    return {
      selectedNode: null,
      candidates: [],
      reason: 'No trusted healthy node satisfies the capability, model, locality, or resource requirements.',
    };
  }

  const selectedNode = availableNodes.find(node => node.nodeId === candidates[0].nodeId) || null;
  return {
    selectedNode,
    candidates,
    reason: `Selected ${selectedNode?.nodeId} using policy-compatible capability, locality, trust, and resource filters.`,
  };
}