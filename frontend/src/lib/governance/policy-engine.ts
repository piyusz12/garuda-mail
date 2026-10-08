import { normalizeUserRole, type UserRole } from '@/lib/roles';

export type PolicyEffect = 'allow' | 'deny' | 'approval_required';
export type PolicyDecision = 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DataClassification = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' | 'TOP_SECRET';

export interface GovernanceRequest {
  action: string;
  resource?: string;
  dataClassification?: DataClassification;
  requestedModel?: string;
  tools?: string[];
  networkMode?: 'local' | 'air-gapped' | 'external';
}

export interface GovernancePolicy {
  id: string;
  name: string;
  subjectRoles: UserRole[];
  actions: string[];
  resources: string[];
  dataClasses?: DataClassification[];
  effect: PolicyEffect;
  priority: number;
  reason: string;
}

export interface GovernanceDecision {
  decision: PolicyDecision;
  risk: RiskLevel;
  matchedPolicies: string[];
  reason: string;
  requiresApproval: boolean;
  allowedModels: string[];
  allowedTools: string[];
}

const CLASSIFICATION_ORDER: DataClassification[] = [
  'PUBLIC',
  'INTERNAL',
  'CONFIDENTIAL',
  'RESTRICTED',
  'TOP_SECRET',
];

export const DEFAULT_POLICIES: GovernancePolicy[] = [
  {
    id: 'policy-air-gapped-network',
    name: 'Air-Gapped Network Boundary',
    subjectRoles: ['admin', 'officer', 'user'],
    actions: ['network.external_request', 'model.cloud_inference', 'tool.browser.fetch'],
    resources: ['*'],
    effect: 'deny',
    priority: 1000,
    reason: 'External network access is disabled in air-gapped mode.',
  },
  {
    id: 'policy-top-secret-local-models',
    name: 'Restricted Data Local Inference',
    subjectRoles: ['admin', 'officer', 'user'],
    actions: ['model.cloud_inference'],
    resources: ['*'],
    dataClasses: ['RESTRICTED', 'TOP_SECRET'],
    effect: 'deny',
    priority: 950,
    reason: 'Restricted data may only use approved local inference.',
  },
  {
    id: 'policy-user-shell-deny',
    name: 'Normal User Shell Deny',
    subjectRoles: ['user'],
    actions: ['tool.shell.execute', 'tool.python.execute'],
    resources: ['*'],
    effect: 'deny',
    priority: 900,
    reason: 'Normal users cannot execute host or interpreter tools.',
  },
  {
    id: 'policy-officer-shell-approval',
    name: 'Authorized Shell Approval',
    subjectRoles: ['officer'],
    actions: ['tool.shell.execute', 'tool.python.execute'],
    resources: ['sandbox'],
    effect: 'approval_required',
    priority: 800,
    reason: 'Authorized tool execution requires human approval in a sandbox.',
  },
  {
    id: 'policy-admin-sandbox-tools',
    name: 'Administrator Sandbox Tools',
    subjectRoles: ['admin'],
    actions: ['tool.shell.execute', 'tool.python.execute'],
    resources: ['sandbox'],
    effect: 'allow',
    priority: 700,
    reason: 'Administrators may use approved sandbox tools.',
  },
  {
    id: 'policy-document-query',
    name: 'Document Query Access',
    subjectRoles: ['admin', 'officer', 'user'],
    actions: ['document.query', 'rag.query'],
    resources: ['document'],
    dataClasses: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'],
    effect: 'allow',
    priority: 500,
    reason: 'Authenticated users may query approved document classifications.',
  },
  {
    id: 'policy-local-inference',
    name: 'Approved Local Inference',
    subjectRoles: ['admin', 'officer', 'user'],
    actions: ['model.inference'],
    resources: ['fabric-workload'],
    dataClasses: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'],
    effect: 'allow',
    priority: 500,
    reason: 'Authenticated users may schedule approved local inference for permitted data.',
  },
  {
    id: 'policy-admin-restricted-query',
    name: 'Administrator Restricted Query',
    subjectRoles: ['admin', 'officer'],
    actions: ['document.query', 'rag.query'],
    resources: ['document'],
    dataClasses: ['RESTRICTED', 'TOP_SECRET'],
    effect: 'allow',
    priority: 600,
    reason: 'Privileged users may query restricted documents subject to audit.',
  },
  {
    id: 'policy-privileged-restricted-inference',
    name: 'Privileged Restricted Inference',
    subjectRoles: ['admin', 'officer'],
    actions: ['model.inference'],
    resources: ['fabric-workload'],
    dataClasses: ['RESTRICTED', 'TOP_SECRET'],
    effect: 'allow',
    priority: 600,
    reason: 'Privileged users may schedule restricted inference on approved local nodes.',
  },
];

function matches(value: string | undefined, patterns: string[]): boolean {
  return Boolean(value && patterns.some(pattern => pattern === '*' || pattern === value));
}

function matchesClassification(
  classification: DataClassification | undefined,
  allowed: DataClassification[] | undefined
): boolean {
  if (!allowed) return true;
  return Boolean(classification && allowed.includes(classification));
}

export function calculateRisk(request: GovernanceRequest): RiskLevel {
  const classification = request.dataClassification || 'INTERNAL';
  const sensitivity = CLASSIFICATION_ORDER.indexOf(classification);
  const toolRisk = (request.tools || []).some(tool =>
    ['tool.shell.execute', 'tool.python.execute', 'tool.database.query'].includes(tool)
  );

  if (toolRisk && sensitivity >= CLASSIFICATION_ORDER.indexOf('RESTRICTED')) return 'CRITICAL';
  if (toolRisk || request.networkMode === 'external') return 'HIGH';
  if (sensitivity >= CLASSIFICATION_ORDER.indexOf('CONFIDENTIAL')) return 'MEDIUM';
  return 'LOW';
}

export function evaluatePolicy(
  role: string | undefined,
  request: GovernanceRequest,
  policies: GovernancePolicy[] = DEFAULT_POLICIES
): GovernanceDecision {
  const normalizedRole = normalizeUserRole(role);
  const airGapped = process.env.AIR_GAPPED_MODE === 'true' || request.networkMode === 'air-gapped';
  const effectiveRequest = {
    ...request,
    resource: request.resource || 'document',
    dataClassification: request.dataClassification || 'INTERNAL',
  };
  const matched = policies
    .filter(policy =>
      (policy.id !== 'policy-air-gapped-network' || airGapped) &&
      policy.subjectRoles.includes(normalizedRole) &&
      matches(effectiveRequest.action, policy.actions) &&
      matches(effectiveRequest.resource, policy.resources) &&
      matchesClassification(effectiveRequest.dataClassification, policy.dataClasses)
    )
    .sort((left, right) => right.priority - left.priority);

  const forcedNetworkDeny = airGapped && (
    effectiveRequest.action === 'network.external_request' ||
    effectiveRequest.action === 'model.cloud_inference' ||
    effectiveRequest.action === 'tool.browser.fetch'
  );
  const winner = forcedNetworkDeny
    ? DEFAULT_POLICIES.find(policy => policy.id === 'policy-air-gapped-network')
    : matched[0];
  const risk = calculateRisk(effectiveRequest);

  if (!winner) {
    return {
      decision: 'DENY',
      risk,
      matchedPolicies: [],
      reason: 'No policy explicitly permits this operation.',
      requiresApproval: false,
      allowedModels: [],
      allowedTools: [],
    };
  }

  const decision: PolicyDecision = winner.effect === 'allow'
    ? 'ALLOW'
    : winner.effect === 'approval_required'
      ? 'APPROVAL_REQUIRED'
      : 'DENY';

  return {
    decision,
    risk,
    matchedPolicies: matched.map(policy => policy.id),
    reason: winner.reason,
    requiresApproval: decision === 'APPROVAL_REQUIRED',
    allowedModels: decision === 'ALLOW' ? ['local-approved'] : [],
    allowedTools: decision === 'ALLOW' ? (request.tools || []) : [],
  };
}