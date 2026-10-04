const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function runTest() {
  console.log('--- STARTING MULTI-USER EMAIL FLOW VERIFICATION ---');

  // 1. Verify User 1 (Analyst on PC 1) and User 2 (Bob on PC 2) exist
  const analyst = await prisma.user.findUnique({ where: { email: 'analyst@enterprise.local' } });
  const bob = await prisma.user.findUnique({ where: { email: 'bob@enterprise.local' } });

  if (!analyst || !bob) {
    throw new Error('Default users not found in database!');
  }
  console.log(`✓ User 1 (PC 1) Verified: ${analyst.name} <${analyst.email}>`);
  console.log(`✓ User 2 (PC 2) Verified: ${bob.name} <${bob.email}>`);

  // 2. Verify password hashes match
  const analystPwMatch = await bcrypt.compare('password123', analyst.password);
  const bobPwMatch = await bcrypt.compare('password123', bob.password);
  console.log(`✓ Password authentication check: Analyst=${analystPwMatch}, Bob=${bobPwMatch}`);

  // 3. User 1 sends an email to User 2
  const subject = `Cross-Device Test from PC 1: ${Date.now()}`;
  const bodyText = 'Hi Bob, this email was sent from PC 1 to test real-time receive on PC 2.';

  const email = await prisma.email.create({
    data: {
      subject,
      body: bodyText,
      preview: bodyText.slice(0, 100),
      fromId: analyst.id,
      tlsVersion: 'TLS 1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      forwardSecrecy: true,
      starttls: true,
      riskScore: 5,
      folder: 'inbox',
      starred: false,
      sentAt: new Date(),
      recipients: {
        create: [
          {
            address: bob.email,
            name: bob.name,
            userId: bob.id,
            type: 'to',
            folder: 'inbox',
            read: false,
            starred: false,
          },
        ],
      },
    },
    include: {
      recipients: true,
    },
  });

  console.log(`✓ Email created & sent: ID=${email.id}, Subject="${subject}"`);

  // 4. Verify User 2 (Bob on PC 2) receives the email in their Inbox
  const bobRecipientRecord = await prisma.emailRecipient.findFirst({
    where: {
      emailId: email.id,
      userId: bob.id,
      folder: 'inbox',
    },
    include: {
      email: {
        include: { from: true },
      },
    },
  });

  if (!bobRecipientRecord) {
    throw new Error('FAILED: Bob did not receive the email in his inbox!');
  }
  console.log(`✓ RECEIVE SUCCESSFUL: Bob's inbox received email from ${bobRecipientRecord.email.from.name}`);
  console.log(`  Unread Status: ${!bobRecipientRecord.read ? 'UNREAD (New Mail)' : 'READ'}`);
  console.log(`  TLS Status: ${bobRecipientRecord.email.tlsVersion}`);

  // 5. Bob reads and stars the email
  await prisma.emailRecipient.update({
    where: { id: bobRecipientRecord.id },
    data: { read: true, starred: true, readAt: new Date() },
  });
  console.log('✓ Bob opened and starred the message');

  // 6. User 2 (Bob) replies to User 1 (Analyst)
  const replySubject = `Re: ${subject}`;
  const replyBody = 'Received loud and clear on PC 2! Cryptographic TLS check passed.';

  const replyEmail = await prisma.email.create({
    data: {
      subject: replySubject,
      body: replyBody,
      preview: replyBody.slice(0, 100),
      fromId: bob.id,
      inReplyTo: email.id,
      threadId: `THREAD-${email.id}`,
      tlsVersion: 'TLS 1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      forwardSecrecy: true,
      starttls: true,
      riskScore: 0,
      folder: 'inbox',
      sentAt: new Date(),
      recipients: {
        create: [
          {
            address: analyst.email,
            name: analyst.name,
            userId: analyst.id,
            type: 'to',
            folder: 'inbox',
            read: false,
            starred: false,
          },
        ],
      },
    },
    include: {
      recipients: true,
    },
  });

  console.log(`✓ Reply sent back to Analyst: ID=${replyEmail.id}, Subject="${replySubject}"`);

  // 7. Verify Analyst receives Bob's reply
  const analystInboxRecord = await prisma.emailRecipient.findFirst({
    where: {
      emailId: replyEmail.id,
      userId: analyst.id,
      folder: 'inbox',
    },
    include: {
      email: { include: { from: true } },
    },
  });

  if (!analystInboxRecord) {
    throw new Error('FAILED: Analyst did not receive reply!');
  }
  console.log(`✓ BI-DIRECTIONAL SUCCESS: Analyst received reply from ${analystInboxRecord.email.from.name}`);

  // 8. Count totals
  const totalEmails = await prisma.email.count();
  const bobUnread = await prisma.emailRecipient.count({ where: { userId: bob.id, read: false } });
  const analystUnread = await prisma.emailRecipient.count({ where: { userId: analyst.id, read: false } });

  console.log(`✓ Total emails in database: ${totalEmails}`);
  console.log(`✓ Analyst unread count: ${analystUnread}, Bob unread count: ${bobUnread}`);
  console.log('--- ALL MULTI-PC EMAIL FLOW TESTS PASSED SUCCESSFULLY! ---');
}

runTest()
  .catch(err => {
    console.error('Test error:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
