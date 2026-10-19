# GARUDA (SIH26159) — Two-Computer Physical LAN Demonstration Runbook

## 1. Physical Demonstration Topology

This guide describes how to run and demonstrate the complete GARUDA application between **two separate physical computers** connected to the same local network (Wi-Fi or Ethernet switch).

```
+-----------------------------------------------------------------------------------+
|                        LOCAL AREA NETWORK (e.g. 192.168.1.0/24)                   |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|   +------------------------------------+    +---------------------------------+   |
|   |            PC-A (HOST)             |    |         PC-B (CLIENT)           |   |
|   |   IP: 192.168.1.105                |    |   IP: 192.168.1.112             |   |
|   |  - Next.js Web Gateway (Port 3000) |    |  - Browser pointing to:         |   |
|   |  - FastAPI Forensic API (Port 8000)|    |    http://192.168.1.105:3000    |   |
|   |  - Zero-Knowledge Store            |    |  - Independent WebCrypto keys   |   |
|   |  - Alice's Authenticated Session   |    |  - Bob's Authenticated Session  |   |
|   +------------------------------------+    +---------------------------------+   |
|                     ▲                                       │                     |
|                     └────────── Envelopes & Telemetry ──────┘                     |
+-----------------------------------------------------------------------------------+
```

---

## 2. Step-by-Step Setup on PC-A (Host Machine)

### Step 2.1: Discover PC-A's Local LAN IP Address
Open PowerShell on PC-A:
```powershell
ipconfig
```
Look for the **IPv4 Address** under your active Wi-Fi or Ethernet adapter (e.g. `192.168.1.105`).

### Step 2.2: Configure Windows Defender Firewall
Allow inbound connections to ports 3000 and 8000:
```powershell
# Run PowerShell as Administrator:
New-NetFirewallRule -DisplayName "GARUDA Web Gateway" -Direction Inbound -LocalPort 3000 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "GARUDA Forensic Backend" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
```

### Step 2.3: Start Services Bound to All Network Interfaces (`0.0.0.0`)
1. **Start the Web Gateway (Terminal 1):**
   ```powershell
   cd "C:\garuda mail\frontend"
   npm run dev
   ```
   *(Notice: Next.js starts with `-H 0.0.0.0`, allowing access from other computers on the LAN).*

2. **Start the Forensic Backend (Terminal 2):**
   ```powershell
   cd "C:\garuda mail"
   python run.py server
   ```
   *(FastAPI starts listening on port 8000).*

---

## 3. Step-by-Step Setup on PC-B (Remote Client Machine)

1. Open any modern web browser (Chrome, Edge, Firefox, Brave) on PC-B.
2. Navigate to:
   ```
   http://192.168.1.105:3000
   ```
   *(Replace `192.168.1.105` with PC-A's actual LAN IP).*
3. The GARUDA login portal appears immediately.

---

## 4. End-to-End Judging Workflow Demonstration

### Phase A: Independent Authenticated Sessions
1. On **PC-A**: Sign in as **Alice / Defense Analyst** (`user@garudamail.local`).
2. On **PC-B**: Sign in as **Bob / Colleague** (`bob@enterprise.local`).
3. Observe the **WhatsApp-style Live Presence Bar**:
   - PC-A sees Bob marked with a glowing **green "Active now" indicator**.
   - PC-B sees Alice marked with a glowing **green "Active now" indicator**.

### Phase B: Cryptographic Key Pair Registration & Fingerprint Verification
1. On **PC-A**: Navigate to **Cryptography -> Key Management & Fingerprint Trust**.
   - Enter a passphrase (e.g. `Passphrase2026!`) and click **Generate & Register Key**.
   - Note Alice's SHA-256 fingerprint (e.g. `SHA256:E0:15:6A:8A:...`).
2. On **PC-B**: Do the same for Bob. Note Bob's fingerprint.
3. On **PC-A**: Locate Bob in the Peer Directory and click **Mark as Trusted**.
   - Open **Compare Fingerprints** to visually confirm Bob's public key matches out-of-band.

### Phase C: Asymmetric End-to-End Encrypted Message Exchange
1. On **PC-A**: Click **Compose** or use the **Quick Mail Drawer**.
   - Recipient: `bob@enterprise.local`
   - Subject: `Classified Operation Phoenix`
   - Body: `Confidential deployment coordinates for sector 4. Encrypted with RSA-OAEP + AES-256-GCM.`
   - Protocol: `Auto-Dispatcher` or `Garuda LAN P2P Mesh`.
   - Click **Dispatch Secure Mail**.
2. On **PC-B**: Instantly observe the new message arriving in Bob's Inbox.
   - Click to open the message.
   - Click **Inspect Ciphertext**: view raw Base64 AES-256-GCM ciphertext.
   - Click **Decrypted Plaintext**: view decrypted message.
   - Click **Verify Cryptographic Signatures**: confirms Alice's RSA-PSS digital signature and GCM authentication tag.

### Phase D: Zero-Knowledge Verification
1. On **PC-A**: Open the database or inspect server memory:
   - Verify that the server stores ONLY the encrypted envelope string (`<!--GARUDA-E2EE-V2-->{...}<!--END-E2EE-V2-->`).
   - The server administrator CANNOT read the message body without Bob's private key.

### Phase E: Sentinel Forensic Capture Ingestion & Analysis
1. On **PC-A**: Navigate to **Forensics / Analysis** (`/analysis`).
2. Upload the capture file `pcaps/smtp_starttls.pcap` or an active LAN capture:
   - The engine validates magic bytes (`0xa1b2c3d4`).
   - Reassembles TCP streams and traces STARTTLS cryptographic upgrade.
   - Extracts Normalized Cryptographic Evidence (Phase 8).
   - Evaluates Deterministic Policy Engine (Phase 9) and displays the Cryptographic Risk Score (CRS).
   - Generates the CycloneDX CBOM and NIST FIPS 203 Post-Quantum Readiness rating.
3. Click **Download Forensic Audit Report** to export the machine-readable JSON security report.
