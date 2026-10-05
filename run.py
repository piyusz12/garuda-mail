#!/usr/bin/env python3
"""
Garuda Mail - Unified Root CLI Runner
Allows executing any forensic engine phase, web frontend, or PCAP pipeline from the repository root.
"""

import sys
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
FRAMEWORK_DIR = ROOT_DIR / "email-forensic-framework"
FRONTEND_DIR = ROOT_DIR / "frontend"

def run_cmd(cmd, cwd=FRAMEWORK_DIR):
    print(f"\n=======================================================")
    print(f" Executing: {' '.join(cmd)}")
    print(f" Working Directory: {cwd}")
    print(f"=======================================================\n")
    resolved_cmd = list(cmd)
    if sys.platform == "win32" and resolved_cmd and resolved_cmd[0] in ("npm", "npx"):
        resolved_cmd[0] = f"{resolved_cmd[0]}.cmd"
    return subprocess.run(resolved_cmd, cwd=str(cwd), shell=(sys.platform == "win32"))

def show_help():
    print("""
Garuda Mail Unified Runner
Usage: python run.py [COMMAND] [ARGS...]

Available Commands:
  all               Run the end-to-end multi-phase forensic demonstration
  server            Start the FastAPI REST backend server on port 8000
  ingest [PCAP]     Ingest a PCAP with main.py (default: pcaps/smtp_starttls.pcap)
  phase2            Run Phase 2 email protocol & encryption transition demo
  orchestrator      Run Phase 9 End-to-End Orchestrator (Phases 1-8)
  phase20           Run Phase 20 Privacy-Preserving Federated Intelligence demo
  phase23           Run Phase 23 Autonomous Threat Hunting & Detection demo
  phase24           Run Phase 24 Autonomous Incident Response & SOAR demo
  phase25           Run Phase 25 Autonomous Security Operations & Closed-Loop Defense demo
  web               Launch the interactive Vite Forensic Telemetry Dashboard (port 5173)
  next              Launch the Next.js Enterprise Findings & Session Portal (port 3000)
  test              Run the pytest test suite across all forensic phases
""")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help", "help"]:
        show_help()
        return

    cmd = sys.argv[1].lower()
    args = sys.argv[2:]

    if cmd == "all":
        print("\n>>> [1/5] Running Phase 2 Protocol & Encryption Detection...")
        run_cmd([sys.executable, "run_phase2.py"])

        print("\n>>> [2/5] Running Phase 9 End-to-End Multi-Phase Orchestrator...")
        run_cmd([sys.executable, "phase_9_orchestrator_cli.py", "analyze", "pcaps/smtp_starttls.pcap"])

        print("\n>>> [3/5] Running Phase 20 Federated Intelligence...")
        run_cmd([sys.executable, "phase_20_federated_intelligence.py", "demo"])

        print("\n>>> [4/5] Running Phase 23 Autonomous Threat Hunting...")
        run_cmd([sys.executable, "phase_23_autonomous_threat_hunting.py", "demo"])

        print("\n>>> [5/5] Running Phase 24 Autonomous Incident Response...")
        run_cmd([sys.executable, "phase_24_autonomous_incident_response.py", "demo"])

        print("\n[+] All core forensic framework demonstrations completed successfully!")

    elif cmd == "server":
        run_cmd([sys.executable, "server.py"])

    elif cmd == "ingest":
        pcap = args[0] if args else "pcaps/smtp_starttls.pcap"
        run_cmd([sys.executable, "main.py", "ingest", pcap])

    elif cmd == "phase2":
        run_cmd([sys.executable, "run_phase2.py"])

    elif cmd == "orchestrator":
        pcap = args[0] if args else "pcaps/smtp_starttls.pcap"
        run_cmd([sys.executable, "phase_9_orchestrator_cli.py", "analyze", pcap])

    elif cmd == "phase20":
        run_cmd([sys.executable, "phase_20_federated_intelligence.py", "demo"])

    elif cmd == "phase23":
        run_cmd([sys.executable, "phase_23_autonomous_threat_hunting.py", "demo"])

    elif cmd == "phase24":
        run_cmd([sys.executable, "phase_24_autonomous_incident_response.py", "demo"])

    elif cmd == "phase25":
        run_cmd([sys.executable, "phase_25_autonomous_security_operations.py", "demo"])

    elif cmd == "web":
        run_cmd(["npm", "run", "dev"], cwd=ROOT_DIR)

    elif cmd == "next":
        run_cmd(["npm", "run", "dev"], cwd=FRONTEND_DIR)

    elif cmd == "test":
        run_cmd([sys.executable, "-m", "pytest", "tests/"])

    else:
        print(f"Unknown command: '{cmd}'")
        show_help()

if __name__ == "__main__":
    main()
