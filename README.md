# Garuda Mail — AI-Assisted Passive Network Forensic Framework & Autonomous SOAR Remediation Platform

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Vite 6](https://img.shields.io/badge/Vite-6.0+-646CFF.svg)](https://vite.dev/)
[![Tests](https://img.shields.io/badge/Tests-189%2F189%20Passing-brightgreen.svg)](tests/)
[![Closed-Loop Defense](https://img.shields.io/badge/Closed--Loop%20Defense-Phase%2025%20SOC-cyan.svg)](phase_25_autonomous_security_operations.py)
[![License: Proprietary](https://img.shields.io/badge/License-Enterprise-red.svg)](#)

> **Enterprise Cryptographic Security Assessment, Passive Telemetry Analysis, Autonomous Threat Hunting, SOAR Orchestration, and Closed-Loop Defensive Operations for Enterprise Email Infrastructures.**

---

## 1. Executive Summary

**Garuda Mail** is a dual-tier passive network forensics and response orchestration platform engineered for enterprise mail transfer agents (MTAs), webmail services, and mail client infrastructures (SMTP, IMAP, POP3). 

The platform merges:
1. **Interactive Client Telemetry Dashboard (`garuda-mail/`)**: In-browser PCAP parsing, TCP stream reassembly, TLS handshake dissection, JA4+ fingerprinting, real-time Chart.js posture analytics, and SOAR Incident Operations Center.
2. **Autonomous Python Forensic Engine (`email-forensic-framework/`)**: An end-to-end passive forensic pipeline spanning **Phases 1 through 24**, culminating in autonomous threat hunting, continuous detection engineering, lakehouse backtesting, automated hypothesis testing, SOAR response playbooks, Four-Eyes cryptographic approvals, canary remediations, multi-layer telemetry verification, and post-incident watchers.

```
       PASSIVE NETWORK CAPTURE (PCAP / PCAPNG)
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                 GARUDA FORENSIC CORE                    │
│                                                         │
│  [Stream Reassembly] ──► [Protocol Classification]      │
│  (Ethernet/IP/TCP)         (SMTP, IMAP, POP3)           │
│                                │                        │
│  [Cryptographic Posture] ◄─────┴──────► [Forensic Lake] │
│  (TLS 1.3, JA4, Ciphers)               (Parquet/DuckDB) │
└──────────────────────────┬──────────────────────────────┘
                           │
         ┌─────────────────┴──────────────────┐
         ▼                                    ▼
┌──────────────────────────────┐   ┌──────────────────────────────┐
│     PHASE 23 & 24 ENGINES    │   │    WEB FORENSIC DASHBOARD    │
│  • Autonomous Threat Hunting │   │  • In-Browser PCAP Ingestion │
│  • HQL Query Execution       │   │  • Real-Time Threat Gauges   │
│  • Incident Qualification    │   │  • Stream Timeline Dissector │
│  • Digital Twin Simulation   │   │  • JA4 Signature Matcher     │
│  • Four-Eyes Approvals       │   │  • CVE / CWE Risk Matrix     │
│  • Canary Remediation        │   │  • Incident Ops Center UI    │
│  • Telemetry Verification    │   │  • Multi-Signature Signoff   │
│  • Post-Incident Monitoring  │   │  • Evidence Bundle Export    │
└──────────────────────────────┘   └──────────────────────────────┘
```

---

## 2. Platform Architecture & Evolution

| Phase Range | Capability Domain | Key Modules |
| :--- | :--- | :--- |
| **Phases 1–5** | Protocol Detection & Session Reassembly | `app/protocol/smtp`, `app/protocol/imap`, `app/protocol/pop3`, `app/models/session.py` |
| **Phases 6–7** | State Transitions & TLS Boundary Identification | `tests/test_phase6_sessions.py`, `tests/test_phase7_transition.py` |
| **Phases 8–12** | Presentation, Orchestration & Enterprise Platform | `phase_8_presentation_export_engine.py` through `phase_12_enterprise_platform.py` |
| **Phases 13–18** | GenAI, Forensic Digital Twins & Self-Healing Assurance | `phase_13_federated_intelligence_genai.py` through `phase_18_security_assurance.py` |
| **Phases 19–20** | Real-Time Streaming Fabric & Federated Intelligence | `phase_19_real_time_streaming_fabric.py`, `phase_20_federated_intelligence.py` |
| **Phase 21** | Cryptographic Agility & Post-Quantum Cryptography (PQC) | `phase_21_cryptographic_agility_pqc.py` (Kyber/Dilithium readiness) |
| **Phase 22** | Forensic Data Lakehouse & Multi-Year Memory | `phase_22_forensic_data_lakehouse.py` (Parquet, Sessions, Lineage) |
| **Phase 23** | Autonomous Threat Hunting & Detection Engineering | `phase_23_autonomous_threat_hunting.py` + 8 modular packages |
| **Phase 24** | Autonomous Incident Response & SOAR Orchestration | `phase_24_autonomous_incident_response.py` + 9 modular packages |
| **Phase 25** | **Autonomous Security Operations & Closed-Loop Defense** | **`phase_25_autonomous_security_operations.py` + `security_operations/` + `detection_engineering/`** |

---

## 3. Phase 23 & Phase 24 Architecture

### Phase 23 — Detection Engineering & Threat Hunting
Phase 23 transforms the forensic lakehouse into an active, self-testing, autonomous defensive engine:
- **Detection Engineering (`detection/`)**: Rule lifecycle (`DRAFT` -> `TESTING` -> `CANARY` -> `ACTIVE`), confidence scoring, and version rollback registry.
- **Autonomous Threat Hunting (`hunting/`)**: Hunt Query Language (HQL) parser, recurring cron/interval hunters, and candidate extraction.
- **Hypothesis Formulation & Testing (`hypothesis/`)**: Abductive hypothesis generator with dual supporting/counter-evidence evaluators.

### Phase 24 — Autonomous Incident Response & SOAR Control Plane
Phase 24 adds the operational decision, remediation, and verification layer:

```
                      PHASE 23
                DETECTION / HUNTING
                       │
                       ▼
                 FINDING / CASE
                       │
                       ▼
             INCIDENT MANAGER (`incident/`)
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
     TRIAGE          IMPACT         CONTEXT
        │              │              │
        └──────────────┼──────────────┘
                       ▼
             RESPONSE ENGINE (`response/`)
                       │
               ┌───────┼────────┐
               ▼       ▼        ▼
           Playbook  Policy   Approval
               │       │        │
               └───────┼────────┘
                       ▼
          ACTION ORCHESTRATOR (`response/`)
                       │
        ┌──────────────┼────────────────┐
        ▼              ▼                ▼
     Network         Endpoint        Identity
      Action           Action          Action
        │              │                │
        └──────────────┼────────────────┘
                       ▼
           VERIFICATION (`verification/`)
                       │
                 ┌─────┴─────┐
                 ▼           ▼
              Success      Failure
                 │           │
                 ▼           ▼
              Monitor      Rollback
           (`monitoring/`) (`response/`)
                 │           │
                 └─────┬─────┘
                       ▼
            POST-INCIDENT (`reporting/`)
                       │
                       ▼
               LESSONS / TUNING
                       │
                       ▼
                  PHASE 23
                IMPROVEMENT LOOP
```

---

## 4. Repository Layout

```text
garuda-mail/
├── .gitignore                                 # Git rules for Node, Vite, Python, Logs & Artifacts
├── README.md                                  # Executive platform overview & operations manual
├── package.json                               # Web application dependencies (Vite, Chart.js, jsPDF)
├── index.html                                 # Clean web entrypoint with Google Fonts
│
├── src/                                       # Web Frontend Source
│   ├── main.js                                # Interactive forensic dashboard & SOAR Incident Ops Center
│   ├── index.css                              # 1,489-line cybersecurity glassmorphism design system
│   ├── core/                                  # In-Browser Binary Analyzers
│   │   ├── pcap-parser.js                     # Binary PCAP format stream parser
│   │   ├── protocol-identifier.js             # Heuristic protocol classifier (SMTP/IMAP/POP3)
│   │   └── tcp-reassembly.js                  # In-browser TCP stream defragmenter
│   ├── data/                                  # Forensic Intelligence Catalogs
│   │   ├── cipher-database.js                 # RFC 9325 / NIST cipher suite ratings
│   │   ├── cve-mappings.js                    # CVE/CWE vulnerability cross-references
│   │   ├── demo-data.js                       # Realistic 85-flow synthetic forensic telemetry
│   │   └── ja4-signatures.js                  # Curated JA4+ fingerprint database
│   └── utils/                                 # Shared Utilities
│       ├── binary-reader.js                   # Big/Little-endian ArrayBuffer reader
│       ├── constants.js                       # Ports, TLS record constants & bitmasks
│       └── formatters.js                      # Byte, duration, timestamp, and risk formatters
│
└── email-forensic-framework/                  # Python Forensic Framework (Phases 1–24)
    ├── requirements.txt                       # Core framework dependencies
    ├── main.py                                # CLI entrypoint
    ├── run_phase2.py                          # Phase 2 regression test & analysis runner
    ├── phase_23_autonomous_threat_hunting.py  # Phase 23 Platform Runner, CLI & REST server
    ├── phase_24_autonomous_incident_response.py # Phase 24 Platform Runner, CLI & REST server
    │
    ├── incident/                              # Phase 24: Incident Management
    │   ├── models.py                          # Incident, IncidentStatus, Severity, Priority
    │   ├── triage.py                          # Criticality & recurrence enrichment
    │   ├── priority.py                        # P1-P4 Multi-dimensional scoring
    │   ├── lifecycle.py                       # 16-State Lifecycle State Machine
    │   └── manager.py                         # Finding-to-incident qualification & reopening
    │
    ├── response/                              # Phase 24: Response Orchestration
    │   ├── risk.py                            # R0 to R4 Risk Classifications
    │   ├── actions.py                         # ResponseAction contracts & action hashes
    │   ├── policy.py                          # Policy-as-code evaluation engine
    │   ├── approval.py                        # Four-Eyes multi-signature approval engine
    │   ├── planner.py                         # Phased canary rollout planner
    │   ├── rollback.py                        # Reverse-order rollback engine
    │   └── orchestrator.py                    # Concurrency change locks & idempotency
    │
    ├── playbooks/                             # Phase 24: Standard Response Playbooks
    │   ├── models.py                          # Playbook & PlaybookStep definitions
    │   ├── registry.py                        # Preloaded playbooks (Crypto regression, certs, JA4)
    │   └── engine.py                          # Regression simulator (v1 vs v2) & adaptive tuning
    │
    ├── connectors/                            # Phase 24: Response Connectors
    │   ├── base.py                            # BaseResponseConnector & health checks
    │   ├── firewall.py                        # Bounded quarantine, JA4 block, ACL
    │   ├── pki.py                             # Certificate replacement & revocation
    │   ├── endpoint.py                        # MTA daemon config & evidence preservation
    │   ├── identity.py                        # Session revocation & credential expiry
    │   ├── ticketing.py                       # ITSM change request synchronization
    │   ├── notifications.py                   # Multi-channel alerts (SOC, PKI, PagerDuty)
    │   └── registry.py                        # ActionType-to-connector routing
    │
    ├── simulation/                            # Phase 24: Pre-Response Safety Controls
    │   ├── blast_radius.py                    # Dependency graph traversal (scope ratio)
    │   ├── digital_twin.py                    # Recorded traffic compatibility assessment
    │   └── dry_run.py                         # Non-mutating preview reports
    │
    ├── verification/                          # Phase 24: Remediation Verification
    │   ├── config.py                          # Daemon configuration snapshot verifier
    │   ├── telemetry.py                       # Passive network wire verifier (zero legacy sessions)
    │   ├── recovery.py                        # Multi-layer service & traffic recovery health
    │   └── engine.py                          # Consolidated verification verdict (PASS/FAIL)
    │
    ├── monitoring/                            # Phase 24: Post-Incident Monitoring
    │   ├── watchers.py                        # Multi-interval watchers (1h, 24h, 7d, 30d, 90d)
    │   ├── recurrence.py                      # Telemetry recurrence detector
    │   └── reopening.py                       # Automated incident reopening & lineage linking
    │
    ├── audit/                                 # Phase 24: Tamper-Evident Audit Ledgers
    │   ├── actions.py                         # Append-only hash-chained action ledger
    │   ├── approvals.py                       # Signature compliance audit log
    │   └── timeline.py                        # ASCII chronological timeline synthesizer
    │
    ├── reporting/                             # Phase 24: Reporting & Continuous Learning
    │   ├── incident_report.py                 # Post-Incident Post-Mortem generator (.MD)
    │   └── lessons.py                         # Lessons learned & Phase 23 feedback engine
    │
    ├── detection/                             # Phase 23: Detection Engineering Package
    ├── hunting/                               # Phase 23: Autonomous Threat Hunting
    ├── hypothesis/                            # Phase 23: Hypothesis Testing
    ├── investigation/                         # Phase 23: Autonomous Investigation
    ├── validation/                            # Phase 23: Continuous Validation
    ├── replay/                                # Phase 23: Scenario Replay
    ├── coverage/                              # Phase 23: ATT&CK Mapping & Gaps
    ├── feedback/                              # Phase 23: Analyst Feedback Loop
    └── tests/                                 # Comprehensive Test Suite (167 Tests)
```

---

## 5. Quick Start Guide

### 5.1 Web Application Setup

```bash
# Navigate to web root
cd "garuda-mail"

# Install dependencies (Vite, Chart.js, jsPDF)
npm install

# Start local development server
npm run dev

# Build production bundle
npm run build
```

### 5.2 Python Forensic Engine Setup

```bash
# Navigate to framework root
cd "garuda-mail/email-forensic-framework"

# Install Python dependencies
pip install -r requirements.txt

# Run complete test suite (167 tests across Phases 1–24)
pytest tests/
```

### 5.3 Phase 23 Autonomous Threat Hunting CLI

```bash
# Run complete Phase 23 demonstration (7 steps with live dashboards)
python phase_23_autonomous_threat_hunting.py demo

# Execute an autonomous HQL threat hunt
python phase_23_autonomous_threat_hunting.py hunt --query "HUNT legacy_tls_recurrence FROM tls_events WHERE tls_version IN ['TLS 1.0', 'TLS 1.1'] WITHIN 90d"

# Conduct an autonomous deep investigation on an entity
python phase_23_autonomous_threat_hunting.py investigate --entity "asset:MTA-07"
```

### 5.4 Phase 24 Autonomous Incident Response CLI

```bash
# Run complete Phase 24 demonstration (10 steps from qualification to post-mortem)
python phase_24_autonomous_incident_response.py demo

# Execute autonomous response on target assets
python phase_24_autonomous_incident_response.py respond --incident "STARTTLS Downgrade Detected" --assets "MTA-07,MTA-01"

# Simulate blast radius and digital twin compatibility
python phase_24_autonomous_incident_response.py simulate --assets "MTA-07,MTA-04"

# Launch Phase 24 REST API microservice (port 8024)
python phase_24_autonomous_incident_response.py serve --port 8024
```

### 5.5 Phase 25 Autonomous Security Operations & Closed-Loop Defense CLI

```bash
# Run complete Phase 25 demonstration (full closed-loop workflow)
python phase_25_autonomous_security_operations.py demo

# Launch Phase 25 SOC & SOAR REST API microservice (port 8025)
python phase_25_autonomous_security_operations.py serve --port 8025
```

---

## 6. Verification & Test Suite

The test suite validates forensic reassembly contracts, Phase 23 threat hunting, Phase 24 SOAR incident response, and the complete Phase 25 autonomous security operations control plane:

```bash
$ pytest tests/
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Thalendra\Desktop\garuda mail\garuda-mail\email-forensic-framework
collected 189 items

tests\coverage\test_coverage_and_feedback.py .....                       [  2%]
tests\detection\test_detection.py .......                                [  6%]
tests\encryption\test_tls_boundary.py ..                                 [  7%]
tests\hunting\test_hunting.py .....                                      [ 10%]
tests\hypothesis\test_hypothesis.py ...                                  [ 11%]
tests\incident\test_incident_management.py ....                          [ 13%]
tests\investigation\test_investigation.py ....                           [ 15%]
tests\phase25\actions\test_actions.py ...                                [ 17%]
tests\phase25\alerts\test_alerts.py ...                                  [ 19%]
tests\phase25\automation\test_automation.py ..                           [ 20%]
tests\phase25\detection_feedback\test_detection_feedback.py ...          [ 21%]
tests\phase25\orchestration\test_orchestration.py ....                   [ 23%]
tests\phase25\playbooks\test_playbooks.py ..                             [ 24%]
tests\phase25\rollback\test_rollback.py .                                [ 25%]
tests\phase25\test_phase25_e2e.py ..                                     [ 26%]
tests\phase25\verification\test_verification.py ..                       [ 27%]
tests\playbooks\test_playbooks.py ...                                    [ 29%]
tests\protocol\test_imap.py ....                                         [ 31%]
tests\protocol\test_pop3.py ...                                          [ 32%]
tests\protocol\test_smtp.py ........                                     [ 37%]
tests\replay\test_replay.py .                                            [ 37%]
tests\response\test_response_orchestration.py .....                      [ 40%]
tests\simulation\test_simulation_blast_radius.py ...                     [ 41%]
tests\test_phase23_e2e.py ..                                             [ 42%]
tests\test_phase24_e2e.py ..                                             [ 43%]
tests\test_phase6_sessions.py ....................................       [ 62%]
tests\test_phase7_transition.py ........................................ [ 84%]
...................                                                      [ 94%]
tests\test_tls_parsing.py ..                                             [ 95%]
tests\validation\test_validation.py ....                                 [ 97%]
tests\verification\test_remediation_verification.py .....                [100%]

======================= 189 passed, 1 warning in 2.29s ========================
```

---

## 7. Security & Compliance Standards

- **RFC 8996**: Complete deprecation validation and automated remediation for TLS 1.0 and TLS 1.1.
- **RFC 9325**: Recommendation for secure use of Transport Layer Security (TLS) and Datagram TLS (DTLS).
- **NIST SP 800-52 Rev 2**: Guidelines for the Selection, Configuration, and Use of TLS Implementations.
- **MITRE ATT&CK for Enterprise**: Direct mapping to Enterprise Matrix techniques:
  - `T1557.002` (Adversary-in-the-Middle: Downgrade / STARTTLS Stripping)
  - `T1573.002` (Encrypted Channel: Asymmetric Cryptography & JA4 Fingerprinting)
  - `T1048.003` (Exfiltration Over Alternative Protocol: Unencrypted Email Body/Auth)
  - `T1588.003` (Obtain Capabilities: Code Signing & Compromised Private Keys)

---

## 8. License & Enterprise Support

Garuda Mail is designed for enterprise cybersecurity operations centers (SOCs), incident response teams, and forensic analysts. Proprietary & Confidential. All rights reserved.
