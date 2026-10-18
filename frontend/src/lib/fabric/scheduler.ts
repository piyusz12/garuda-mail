import type { DataClassification } from '@/lib/governance/policy-engine';
import { listNodes, type FabricNode } from '@/lib/fabric/node-registry';

export interface WorkloadRequest {
  capability: string;
  model?: string;
  minVramGb?: number;
  dataClassification?: DataClassification;
  allowedZones?: string[];
  priority?: 'critical' | 'high' | 'normal' | 'low' | 'background';
  callerId?: string;
}

export interface NodeCandidateScore {
  nodeId: string;
  score: number;
  isEligible: boolean;
  reasons: string[];
  rejectionReason?: string;
  policyScore: number;
  trustScore: number;
  resourceScore: number;
  localityScore: number;
  queuePenalty: number;
}

export interface ScheduleDecision {
  selectedNode: FabricNode | null;
  candidates: NodeCandidateScore[];
  rejectedReasons: Record<string, string>;
  reason: string;
  explanation: string;
  scheduled: boolean;
}

const TRUST_SCORE = { trusted: 100, limited: 50, untrusted: -200, quarantined: -1000 } as const;
const PRIORITY_SCORE = { critical: 35, high: 18, normal: 0, low: -10, background: -25 } as const;

export function scheduleWorkload(request: WorkloadRequest, availableNodes = listNodes()): ScheduleDecision {
  const candidates: NodeCandidateScore[] = [];
  const rejectedReasons: Record<string, string> = {};

  for (const node of availableNodes) {
    let isEligible = true;
    let rejection: string | undefined;
    const reasons: string[] = [];

    // Stage 1: Health & Trust Filter (Section 34.21 & 34.38)
    if (node.status === 'unavailable' || node.status === 'quarantined') {
      isEligible = false;
      rejection = `Node status is ${node.status.toUpperCase()}`;
    } else if (node.trust === 'untrusted' || node.trust === 'quarantined') {
      isEligible = false;
      rejection = `Node trust level is ${node.trust.toUpperCase()} (unauthorized for compute)`;
    }

    // Stage 2: Capability Filter (Section 34.6)
    if (isEligible && !node.capabilities.includes(request.capability)) {
      isEligible = false;
      rejection = `Lacks required capability '${request.capability}'`;
    } else if (isEligible) {
      reasons.push(`Provides capability '${request.capability}'`);
    }

    // Stage 3: Model Availability Filter (Section 34.9)
    if (isEligible && request.model) {
      if (!node.models.includes(request.model)) {
        isEligible = false;
        rejection = `Requested model '${request.model}' not loaded`;
      } else {
        reasons.push(`Model '${request.model}' is READY and loaded`);
      }
    }

    // Stage 4: Sovereign Data Locality Filter (Section 34.11 & 34.30)
    if (isEligible) {
      if (request.dataClassification === 'RESTRICTED' || request.dataClassification === 'TOP_SECRET') {
        if (node.zone !== 'RESTRICTED_AI') {
          isEligible = false;
          rejection = `Data locality violation: ${request.dataClassification} data restricted to RESTRICTED_AI zone (node in ${node.zone})`;
        } else {
          reasons.push('Sovereign data locality verified (RESTRICTED_AI match)');
        }
      } else if (request.dataClassification === 'CONFIDENTIAL') {
        if (node.zone !== 'RESTRICTED_AI' && node.zone !== 'INTERNAL_AI') {
          isEligible = false;
          rejection = `Confidential data forbidden in zone '${node.zone}'`;
        } else {
          reasons.push('Data locality verified for CONFIDENTIAL tier');
        }
      }

      if (isEligible && request.allowedZones && !request.allowedZones.includes(node.zone)) {
        isEligible = false;
        rejection = `Node zone '${node.zone}' not in requested allowed zones`;
      }
    }

    // Stage 5: Resource-Aware VRAM / RAM Filter (Section 34.8)
    const freeVram = Math.max(0, node.vramTotalGb - node.vramUsedGb);
    const requiredVram = request.minVramGb || 0;

    if (isEligible && requiredVram > 0 && freeVram < requiredVram) {
      isEligible = false;
      rejection = `Insufficient VRAM: required ${requiredVram} GB, available ${freeVram.toFixed(1)} GB`;
    } else if (isEligible && requiredVram > 0) {
      reasons.push(`Sufficient VRAM: ${freeVram.toFixed(1)} GB free >= ${requiredVram} GB required`);
    }

    // Stage 6: Scoring Logic (Section 34.48)
    const policyScore = isEligible ? 100 : 0;
    const trustScore = TRUST_SCORE[node.trust] || 0;
    const resourceScore = freeVram * 8 + (node.ramTotalGb - node.ramUsedGb) * 0.5;
    const localityScore = node.zone === 'RESTRICTED_AI' ? 50 : 25;
    const queuePenalty = node.activeJobs * 45 + (node.cpuUsagePct * 0.2);
    const priorityBoost = PRIORITY_SCORE[request.priority || 'normal'] || 0;

    const totalScore = isEligible
      ? policyScore + trustScore + resourceScore + localityScore + priorityBoost - queuePenalty
      : 0;

    if (!isEligible) {
      rejectedReasons[node.nodeId] = rejection || 'Failed filter';
    } else {
      reasons.push(`Trust level '${node.trust}' (+${trustScore})`);
      reasons.push(`Resource headroom: ${freeVram.toFixed(1)} GB VRAM free`);
    }

    candidates.push({
      nodeId: node.nodeId,
      score: Math.round(totalScore * 10) / 10,
      isEligible,
      reasons,
      rejectionReason: rejection,
      policyScore,
      trustScore,
      resourceScore: Math.round(resourceScore * 10) / 10,
      localityScore,
      queuePenalty: Math.round(queuePenalty * 10) / 10,
    });
  }

  const eligibleCandidates = candidates.filter(c => c.isEligible).sort((a, b) => b.score - a.score);

  if (eligibleCandidates.length === 0) {
    return {
      selectedNode: null,
      candidates,
      rejectedReasons,
      reason: 'No trusted healthy node satisfies the capability, model, locality, or resource requirements.',
      explanation: 'All registered nodes were rejected based on policy, locality, trust, or capacity constraints.',
      scheduled: false,
    };
  }

  const bestCandidate = eligibleCandidates[0];
  const selectedNode = availableNodes.find(n => n.nodeId === bestCandidate.nodeId) || null;
  const explanation = `Selected ${bestCandidate.nodeId} (Score: ${bestCandidate.score}). Reasons: ${bestCandidate.reasons.slice(0, 4).join('; ')}.`;

  return {
    selectedNode,
    candidates,
    rejectedReasons,
    reason: `Selected ${selectedNode?.nodeId} using policy-compatible capability, locality, trust, and resource filters.`,
    explanation,
    scheduled: true,
  };
}