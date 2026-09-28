# Phase 30: Enterprise AI Security, AI-SPM, LLM Security & Agent Security

**Phase 30** establishes a comprehensive enterprise control plane and security graph governing models, agents, RAG pipelines, vector databases, and tools. It answers: ***"What exactly is the AI system allowed to know, do, call, modify, and expose?"***

---

## 1. Architectural Highlights

```text
                     USER
                       │
                    IDENTITY  (Phase 27)
                       │
                    WORKLOAD  (Phase 28)
                       │
                    AI AGENT  (Phase 30)
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        MODEL         RAG          TOOLS
     (Inference)    (Vector)       (APIs)
          │            │            │
          └────────────┼────────────┘
                       ▼
                 DATA SECURITY (Phase 29)
                 (Classification & Flows)
                       │
                       ▼
                    AI GRAPH
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       AI-SPM       AI DLP       ANOMALIES
          │            │            │
          └────────────┼────────────┘
                       ▼
                 POLICY ENGINE (Allow / Restrict / Block)
                       │
                       ▼
                   RESPONSE    (Phase 25)
                       │
                   FORENSICS   (Phase 30 Timeline & Snapshots)
                       │
                  VALIDATION   (Phase 26 Continuous Assurance)
```

1. **RAG Trust Boundary (Section 30.19):** Separates trusted system instructions from untrusted retrieved content (`SOURCE = UNTRUSTED DATA`), preventing indirect injection attacks in retrieved chunks from executing privileged actions.
2. **Pre-Retrieval Authorization (Section 30.27):** Enforces data authorization *prior to* vector similarity queries via [`RetrievalAuthorizationEngine`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/rag/retrieval.py#L38-L102) rather than filtering chunks post-retrieval.
3. **Least-Privilege Tool Contracts (Section 30.25):** Capability contracts in [`ToolAuthorizationEngine`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/tools/authorization.py#L18-L81) enforce action-level (`SELECT` vs `DROP`) and table-level access, blocking unauthorized access to customer vaults.
4. **Multi-Dimensional AI Risk Engine (Section 30.49):** Refuses opaque single risk scores; tracks seven decoupled dimensions (Model, Data, Agent, Tool, Network, Supply Chain, and Privacy Risk) in [`AIRiskEngine`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/risk/data.py#L45-L106).
5. **Precision Incident Containment (Section 30.80 Step 7):** When an agent initiates anomalous exfiltration, response selectively severs the dangerous tool (`http_post`) while preserving read/RAG and LLM functionality.

---

## 2. Implemented Modules & Code Structure

### A. Inventory & Models
- [`ai_security/inventory/assets.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/inventory/assets.py): Defines canonical [`AIAsset`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/inventory/assets.py#L43-L78), [`AIAssetType`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/inventory/assets.py#L10-L24), [`ModelLifecycleStatus`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/inventory/assets.py#L26-L33).
- [`ai_security/inventory/discovery.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/inventory/discovery.py): [`AIDiscoveryEngine`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/inventory/discovery.py#L8-L145) discovers sovereign `MODEL-781` on `AI-NODE-04`, `AGENT-41`, `VECTOR-DB-07`, and `RAG-PIPELINE-01`.
- [`ai_security/models/registry.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/registry.py): [`AIModelRegistry`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/registry.py#L46-L106) with lifecycle deprecation tracking.
- [`ai_security/models/provenance.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/provenance.py): [`ModelProvenanceTracker`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/provenance.py#L29-L65) tracking source repos, artifact commit hashes, and author identity.
- [`ai_security/models/integrity.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/integrity.py): [`ModelIntegrityAuditor`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/integrity.py#L24-L60) detecting runtime digest tampering.
- [`ai_security/models/supply_chain.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/supply_chain.py): [`ModelSupplyChainScanner`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/supply_chain.py#L40-L75) detecting unapproved model introductions.
- [`ai_security/models/deployment.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/deployment.py): [`ModelDeploymentManager`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/models/deployment.py#L38-L76) enforcing workload authentication.

### B. Prompts & Responses
- [`ai_security/prompts/classifier.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/prompts/classifier.py): [`PromptClassifier`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/prompts/classifier.py#L32-L75) for PII, PCI, and API key leak detection in prompt payloads.
- [`ai_security/prompts/injection.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/prompts/injection.py): [`PromptInjectionDetector`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/prompts/injection.py#L40-L96) catching jailbreaks, system prompt extractions, and indirect RAG overrides.
- [`ai_security/prompts/policy.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/prompts/policy.py): [`PromptPolicyEngine`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/prompts/policy.py#L41-L103) executing `ALLOW`, `WARN`, `REDACT`, and `BLOCK`.
- [`ai_security/responses/scanner.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/responses/scanner.py): [`ResponseSecurityScanner`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/responses/scanner.py#L33-L75) scanning output for private keys, AWS tokens, and dangerous shell commands.

### C. RAG & Vector Stores
- [`ai_security/rag/knowledge_base.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/rag/knowledge_base.py): [`KnowledgeBaseRegistry`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/rag/knowledge_base.py#L40-L102) scoping `KB-001` (Internal), `KB-002` (Support), and `KB-003` (Restricted).
- [`ai_security/rag/embeddings.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/rag/embeddings.py): [`EmbeddingSecurityTracker`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/rag/embeddings.py#L37-L63) tracking embeddings to source datasets.
- [`ai_security/rag/vectorstores.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/rag/vectorstores.py): [`VectorDatabaseManager`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/rag/vectorstores.py#L35-L79) managing multi-tenant isolation.
- [`ai_security/rag/retrieval.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/rag/retrieval.py): [`RetrievalAuthorizationEngine`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/rag/retrieval.py#L38-L102) pre-query access enforcement.

### D. Agents, Tools & Runtime
- [`ai_security/agents/registry.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/agents/registry.py): [`AgentRegistry`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/agents/registry.py#L41-L97) tracking `AGENT-41`.
- [`ai_security/agents/identity.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/agents/identity.py): [`AgentIdentityManager`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/agents/identity.py#L31-L54) binding agents to Phase 27 Zero Trust identity contexts (`SERVICE-IDENTITY-77`).
- [`ai_security/agents/permissions.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/agents/permissions.py): [`AgentPermissionEvaluator`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/agents/permissions.py#L39-L74) calculating composite access blast radiuses.
- [`ai_security/agents/behavior.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/agents/behavior.py): [`AgentBehaviorAnalytics`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/agents/behavior.py#L43-L98) flagging `AI_BEHAVIOR_ANOMALY` and `TOOL_LOOP_ANOMALY`.
- [`ai_security/tools/authorization.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/tools/authorization.py): [`ToolAuthorizationEngine`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/tools/authorization.py#L18-L81) executing least-privilege permission contracts.
- [`ai_security/tools/invocation.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/tools/invocation.py): [`ToolInvocationInterceptor`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/tools/invocation.py#L40-L108) intercepting and auditing runtime execution.

### E. DLP, Posture, Analytics & Risk
- [`ai_security/dlp/enforcement.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/dlp/enforcement.py): [`AIDLPEnforcementEngine`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/dlp/enforcement.py#L13-L119) with policy simulation.
- [`ai_security/posture/evaluation.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/posture/evaluation.py): [`AISPMEvaluator`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/posture/evaluation.py#L36-L72) verifying rules `AI-SPM-001` through `AI-SPM-007`.
- [`ai_security/posture/drift.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/posture/drift.py): [`AIConfigurationDriftDetector`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/posture/drift.py#L31-L60) detecting unauthorized runtime configuration drift.
- [`ai_security/analytics/anomalies.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/analytics/anomalies.py): [`AIAnomalyDetector`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/analytics/anomalies.py#L42-L74) flagging recursive tool loops and token surges.
- [`ai_security/risk/data.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/risk/data.py): [`AIRiskEngine`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/risk/data.py#L45-L106) calculating distinct scores across all 7 dimensions.

### F. Forensics, Graph & Copilot
- [`ai_security/forensics/timeline.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/forensics/timeline.py): [`AITimelineBuilder`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/forensics/timeline.py#L29-L51) building Section 30.81 chronological timelines.
- [`ai_security/forensics/snapshots.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/forensics/snapshots.py): [`AIForensicSnapshotManager`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/forensics/snapshots.py#L62-L99) computing immutable SHA-256 state snapshots.
- [`ai_security/forensics/evidence.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/forensics/evidence.py): [`AIEvidencePackage`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/forensics/evidence.py#L14-L48) creating court-ready verifiable packages.
- [`ai_graph/traversal.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_graph/traversal.py): [`AIGraph`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_graph/traversal.py#L46-L181) performing attack-path DFS traversals and Digital Twin containment simulations.
- [`ai_security/copilot/investigations.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/copilot/investigations.py): [`AISecurityCopilot`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/ai_security/copilot/investigations.py#L64-L141) diagnosing access permissions and DLP decisions.
- [`phase_30_enterprise_ai_security.py`](file:///c:/Users/Thalendra/Desktop/garuda%20mail/garuda-mail/email-forensic-framework/phase_30_enterprise_ai_security.py): Unified FastAPI control plane server and Typer CLI.

---

## 3. Test Suite & Validation

The test suite covers models, prompts, RAG, agents, tools, DLP, posture, analytics, forensics, and end-to-end scenarios:

```bash
pytest tests/phase30/ -v
```

```text
tests/phase30/test_agents_tools.py::test_agent_registry_and_identity_binding PASSED
tests/phase30/test_agents_tools.py::test_effective_agent_access_evaluation PASSED
tests/phase30/test_agents_tools.py::test_tool_registry_and_risk_levels PASSED
tests/phase30/test_agents_tools.py::test_tool_authorization_contracts_least_privilege PASSED
tests/phase30/test_agents_tools.py::test_tool_invocation_interceptor_audits PASSED
tests/phase30/test_agents_tools.py::test_agent_behavior_analytics_anomaly_and_loop_detection PASSED
tests/phase30/test_agents_tools.py::test_agent_runtime_monitor_steps PASSED
tests/phase30/test_analytics_risk.py::test_ai_anomaly_detection_loops_and_tokens PASSED
tests/phase30/test_analytics_risk.py::test_multi_dimensional_risk_scoring_decoupled PASSED
tests/phase30/test_dlp_posture.py::test_ai_dlp_evaluation_and_blocking PASSED
tests/phase30/test_dlp_posture.py::test_ai_dlp_policy_simulation PASSED
tests/phase30/test_dlp_posture.py::test_ai_spm_posture_evaluation PASSED
tests/phase30/test_dlp_posture.py::test_ai_configuration_drift_detection PASSED
tests/phase30/test_forensics_validation_twin.py::test_ai_forensic_snapshots_and_immutable_hash PASSED
tests/phase30/test_forensics_validation_twin.py::test_ai_timeline_builder_and_evidence_package PASSED
tests/phase30/test_forensics_validation_twin.py::test_ai_security_validation_runner PASSED
tests/phase30/test_forensics_validation_twin.py::test_ai_graph_attack_path_and_digital_twin_simulation PASSED
tests/phase30/test_forensics_validation_twin.py::test_ai_security_copilot_queries_and_dashboard PASSED
tests/phase30/test_models.py::test_model_registry_and_deprecation_lifecycle PASSED
tests/phase30/test_models.py::test_model_provenance_tracking PASSED
tests/phase30/test_models.py::test_model_artifact_integrity_verification PASSED
tests/phase30/test_models.py::test_model_supply_chain_scanning PASSED
tests/phase30/test_models.py::test_model_deployment_security_and_auth PASSED
tests/phase30/test_phase30_e2e.py::test_section_30_80_end_to_end_walkthrough PASSED
tests/phase30/test_phase30_e2e.py::test_section_30_76_rest_api_endpoints PASSED
tests/phase30/test_phase30_e2e.py::test_cross_phase_continuous_validation_and_sovereignty PASSED
tests/phase30/test_prompts_responses.py::test_prompt_classification_and_sensitivity PASSED
tests/phase30/test_prompts_responses.py::test_prompt_injection_and_jailbreak_detection PASSED
tests/phase30/test_prompts_responses.py::test_prompt_policy_enforcement_and_redaction PASSED
tests/phase30/test_prompts_responses.py::test_response_security_scanning_and_blocking PASSED
tests/phase30/test_rag.py::test_knowledge_base_inventory_and_classification PASSED
tests/phase30/test_rag.py::test_embedding_security_and_provenance_link PASSED
tests/phase30/test_rag.py::test_vector_store_tenant_isolation_and_roles PASSED
tests/phase30/test_rag.py::test_pre_retrieval_authorization_enforcement PASSED
tests/phase30/test_rag.py::test_rag_pipeline_configuration_and_listing PASSED

======================== 35 passed in 0.99s ========================
```

Full workspace regression across all phases (Phases 1 through 30):
```text
352 passed, 1 warning in 3.76s (100% passing across all phases)
```

---

## 4. Section 30.80 Incident Lifecycle Walkthrough Verified

```text
Step 1: Agent Discovery       ──► AGENT-41 discovered with MODEL-781, SERVICE-IDENTITY-77, tools [database_query, http_post]
Step 2: Permission Graph      ──► AGENT-41 -> DB-TOOL -> CUSTOMER-DB and AGENT-41 -> HTTP-TOOL -> INTERNET
Step 3: Data Context (Ph 29)  ──► CUSTOMER-DB classified as RESTRICTED
Step 4: Agent Behavior        ──► DB queries 18/req (baseline: 2), HTTP calls 7 (baseline: 0) -> AI_BEHAVIOR_ANOMALY
Step 5: Data Flow             ──► RESTRICTED data routed toward external HTTP endpoint
Step 6: AI DLP                ──► AI-DLP-01 matches: data=RESTRICTED, dest=external -> ACTION: BLOCK
Step 7: Precision Containment ──► Revoked http_post tool while keeping database & RAG operational (CASE-9001)
```