const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding database...');

  // Hash default password
  const hashedPassword = await bcrypt.hash('password123', 10);

  // 1. Create or upsert primary users
  const analyst = await prisma.user.upsert({
    where: { email: 'analyst@enterprise.local' },
    update: {},
    create: {
      name: 'Garuda Analyst',
      email: 'analyst@enterprise.local',
      password: hashedPassword,
      role: 'analyst',
      department: 'Cryptographic SOC',
      avatarColor: '#38BDF8',
    },
  });

  const security = await prisma.user.upsert({
    where: { email: 'security@enterprise.local' },
    update: {},
    create: {
      name: 'Security Operations',
      email: 'security@enterprise.local',
      password: hashedPassword,
      role: 'admin',
      department: 'SecOps Infrastructure',
      avatarColor: '#F43F5E',
    },
  });

  const bob = await prisma.user.upsert({
    where: { email: 'bob@enterprise.local' },
    update: {},
    create: {
      name: 'Bob Henderson',
      email: 'bob@enterprise.local',
      password: hashedPassword,
      role: 'analyst',
      department: 'Network Forensics',
      avatarColor: '#10B981',
    },
  });

  const alice = await prisma.user.upsert({
    where: { email: 'alice@enterprise.local' },
    update: {},
    create: {
      name: 'Alice Vance',
      email: 'alice@enterprise.local',
      password: hashedPassword,
      role: 'analyst',
      department: 'Cryptography & CBOM',
      avatarColor: '#8B5CF6',
    },
  });

  console.log(`Users created: ${analyst.email}, ${security.email}, ${bob.email}, ${alice.email}`);

  // 2. Seed initial rich emails if none exist
  const existingCount = await prisma.email.count();
  if (existingCount === 0) {
    const seedEmails = [
      {
        subject: 'Enterprise Security Assessment — Q3 TLS Configuration Review',
        body: `Hi Team,\n\nPlease find the Q3 email infrastructure security assessment results attached. Key findings:\n\n1. SMTP gateway smtp01.enterprise.local is negotiating TLS 1.0 with several external partners. This is a critical finding as TLS 1.0 has known cryptographic vulnerabilities.\n\n2. The cipher suite TLS_RSA_WITH_AES_128_CBC_SHA lacks forward secrecy. If the server's private key is ever compromised, all past sessions can be decrypted.\n\n3. We detected unusual cipher preference ordering on session SMTP-0192 which triggered our anomaly detection system.\n\nImmediate action items:\n- Deprecate TLS 1.0/1.1 across all MTAs immediately\n- Prioritize ECDHE suites to enforce Forward Secrecy\n- Rotate expired certificates on imap.legacy.corp\n\nFull PCAP captures and CBOM inventory have been indexed in Garuda Mail for forensic review.\n\nRegards,\nSecurity Operations Team`,
        preview: 'Attached findings from the quarterly email infrastructure audit. SMTP gateway smtp01.enterprise.local shows deprecated TLS 1.0 negotiation...',
        fromId: security.id,
        tlsVersion: 'TLS 1.0',
        cipher: 'TLS_RSA_WITH_AES_128_CBC_SHA',
        forwardSecrecy: false,
        starttls: true,
        riskScore: 85,
        folder: 'inbox',
        starred: true,
        recipients: [
          { address: analyst.email, name: analyst.name, userId: analyst.id, folder: 'inbox', read: false, starred: true },
        ],
      },
      {
        subject: 'Plaintext IMAP Transmission Alert — Immediate Remediation Required',
        body: `CRITICAL ALERT — INCIDENT #SEC-2026-0891\n\nAutomated sensor probe has detected unencrypted IMAP traffic on TCP port 143 from internal subnet 10.0.12.0/24.\n\nProtocol analysis confirms:\n- Client requested STARTTLS, server returned -ERR Unrecognized Command\n- Client subsequently transmitted credentials in PLAINTEXT\n- Affected user session: FLOW-00004\n\nMitigation steps executed:\n- Port 143 traffic redirected to quarantine VLAN\n- Credential revocation ticket opened with IAM\n- Forensics team assigned to packet stream extraction\n\nPlease review the attached session flow in the Forensic Sessions tab.\n\nSOC Alert Dispatcher`,
        preview: 'CRITICAL ALERT — Automated sensor probe has detected unencrypted IMAP traffic on TCP port 143 without TLS encryption...',
        fromId: security.id,
        tlsVersion: null,
        cipher: null,
        forwardSecrecy: false,
        starttls: false,
        riskScore: 95,
        folder: 'inbox',
        starred: true,
        recipients: [
          { address: analyst.email, name: analyst.name, userId: analyst.id, folder: 'inbox', read: false, starred: true },
        ],
      },
      {
        subject: 'Post-Quantum Cryptography (PQC) Readiness — CBOM Milestone 2 Update',
        body: `Hello Garuda Forensic Analysts,\n\nWe have completed our Post-Quantum Cryptography (PQC) audit of the email gateway cryptographic bill of materials (CBOM):\n\n- 82% of current MTAs are operating with classical RSA-2048 keys\n- Hybrid post-quantum key exchange (X25519Kyber768Draft00) is now supported on Edge Gateway smtp-pqc.enterprise.local\n- Zero quantum-vulnerable long-lived session keys observed on core infrastructure\n\nCheck out the CBOM workspace in the sidebar to visualize the asset inventory and post-quantum readiness scores.\n\nBest,\nAlice Vance\nCryptography Team`,
        preview: 'Completed audit of email gateway cryptographic bill of materials. Hybrid post-quantum key exchange enabled on Edge Gateway...',
        fromId: alice.id,
        tlsVersion: 'TLS 1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        forwardSecrecy: true,
        starttls: true,
        riskScore: 10,
        folder: 'inbox',
        starred: false,
        recipients: [
          { address: analyst.email, name: analyst.name, userId: analyst.id, folder: 'inbox', read: true, starred: false },
        ],
      },
      {
        subject: 'Investigation Closed: Suspected Downgrade Attack on relay-02',
        body: `Analyst Team,\n\nInvestigation INV-2026-042 regarding the suspected STARTTLS stripping attack on relay-02 has concluded.\n\nRoot Cause: Middlebox firewall configuration pushed an MTU clamp that fragmented the EHLO STARTTLS response packet, causing client fallback.\nResolution: Rule updated to preserve full STARTTLS capability advertisement.\n\nStatus: CLOSED — False Positive (Network Misconfiguration).\n\nThanks,\nBob Henderson`,
        preview: 'Investigation INV-2026-042 regarding the suspected STARTTLS stripping attack on relay-02 has concluded. Root cause: middlebox MTU clamp...',
        fromId: bob.id,
        tlsVersion: 'TLS 1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
        forwardSecrecy: true,
        starttls: true,
        riskScore: 15,
        folder: 'inbox',
        starred: false,
        recipients: [
          { address: analyst.email, name: analyst.name, userId: analyst.id, folder: 'inbox', read: true, starred: false },
        ],
      },
      {
        subject: 'Outbound Security Audit: Partners Gateway Compliance Report',
        body: `To: partner-ops@external-partner.org\n\nThis is an automated delivery confirmation for the monthly security compliance report.\n\nConnection negotiated: TLS 1.3 with Forward Secrecy.\nCertificate validated against CA root store.\n\nGaruda Automated Security Gateway`,
        preview: 'Automated delivery confirmation for monthly security compliance report. Connection negotiated TLS 1.3 with Forward Secrecy...',
        fromId: analyst.id,
        tlsVersion: 'TLS 1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        forwardSecrecy: true,
        starttls: true,
        riskScore: 5,
        folder: 'sent',
        starred: false,
        recipients: [
          { address: 'partner-ops@external-partner.org', name: 'Partner Operations', userId: null, folder: 'sent', read: true, starred: false },
        ],
      },
    ];

    for (const item of seedEmails) {
      const email = await prisma.email.create({
        data: {
          subject: item.subject,
          body: item.body,
          preview: item.preview,
          fromId: item.fromId,
          tlsVersion: item.tlsVersion,
          cipher: item.cipher,
          forwardSecrecy: item.forwardSecrecy,
          starttls: item.starttls,
          riskScore: item.riskScore,
          folder: item.folder,
          starred: item.starred,
          sentAt: new Date(),
          recipients: {
            create: item.recipients.map(r => ({
              address: r.address,
              name: r.name,
              userId: r.userId,
              folder: r.folder,
              read: r.read,
              starred: r.starred,
            })),
          },
        },
      });
      console.log(`Seeded email: ${email.subject}`);
    }
  }

  console.log('Seeding completed successfully!');
}

main()
  .catch(e => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
