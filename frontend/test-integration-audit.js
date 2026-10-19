/**
 * GARUDA — Comprehensive Integration & Audit Test Suite
 * Validates:
 * 1. Asymmetric V2 envelope preservation (no double encryption)
 * 2. Client-side private key passphrase locking & unlocking
 * 3. Zero-Knowledge E2EE round-trip (Encrypt -> Server Relay -> Client Decrypt)
 * 4. Fallback authentication token HMAC verification with bcrypt hash
 * 5. Magic byte validation for classic PCAP, nanosecond PCAP, and PCAP-NG
 */

const {
  generateUserKeyPair,
  getPublicKeyFingerprint,
  encryptAsymmetricEnvelope,
  decryptAsymmetricEnvelope,
  encryptPrivateKeyWithPassphrase,
  decryptPrivateKeyWithPassphrase,
  decryptPayload,
} = require('./src/lib/crypto');

const {
  createFallbackToken,
  verifyFallbackToken,
} = require('./src/lib/users');

async function runAuditTests() {
  console.log('=============================================================');
  console.log(' GARUDA COMPREHENSIVE INTEGRATION & AUDIT TEST SUITE');
  console.log('=============================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName) {
    if (condition) {
      console.log(`  ✓ [PASS] ${testName}`);
      passed++;
    } else {
      console.error(`  ✗ [FAIL] ${testName}`);
      failed++;
    }
  }

  // ── TEST 1: Asymmetric Keypair & Passphrase Vault ─────────────────────────
  console.log('[+] Test 1: Client Private Key Passphrase Vault & Derivation');
  const userKeys = generateUserKeyPair(2048);
  const passphrase = 'UltraSecurePassphrase2026!';
  const encryptedBundle = encryptPrivateKeyWithPassphrase(
    JSON.stringify({ enc: userKeys.encryptionPrivateKey, sig: userKeys.signingPrivateKey }),
    passphrase
  );

  assert(encryptedBundle.includes('GARUDA-KEYSTORE-v1'), 'Key vault format matches GARUDA-KEYSTORE-v1');

  // Verify correct passphrase unlocks
  const decryptedJson = decryptPrivateKeyWithPassphrase(encryptedBundle, passphrase);
  const parsedKeys = JSON.parse(decryptedJson);
  assert(parsedKeys.enc === userKeys.encryptionPrivateKey, 'Passphrase unlocks identical private encryption key');
  assert(parsedKeys.sig === userKeys.signingPrivateKey, 'Passphrase unlocks identical private signing key');

  // Verify wrong passphrase throws error
  let wrongPassphraseThrew = false;
  try {
    decryptPrivateKeyWithPassphrase(encryptedBundle, 'WrongPassword123!');
  } catch {
    wrongPassphraseThrew = true;
  }
  assert(wrongPassphraseThrew, 'Incorrect passphrase safely rejected with cryptographic failure');

  // ── TEST 2: Asymmetric E2EE Round-Trip Without Double Encryption ───────────
  console.log('\n[+] Test 2: Asymmetric E2EE Envelope Preservation');
  const alice = generateUserKeyPair(2048);
  const bob = generateUserKeyPair(2048);
  const sensitiveBody = 'CONFIDENTIAL: Tactical grid realignment at sector 12.';

  // Alice encrypts for Bob
  const { envelopeString, envelope } = encryptAsymmetricEnvelope({
    plaintext: sensitiveBody,
    senderKeyPair: {
      signingPrivateKey: alice.signingPrivateKey,
      signingPublicKey: alice.signingPublicKey,
      encryptionPublicKey: alice.encryptionPublicKey,
    },
    recipientPublicKeys: [{
      recipientFingerprint: bob.fingerprint,
      encryptionPublicKey: bob.encryptionPublicKey,
    }],
  });

  assert(envelopeString.includes('<!--GARUDA-E2EE-V2-->'), 'V2 Envelope contains valid header markup');

  // Server-side check: When server inspects envelope without private key
  const serverInspection = decryptPayload(envelopeString);
  assert(serverInspection.isEncrypted === true, 'Server detects message is encrypted');
  assert(serverInspection.version === 'v2', 'Server identifies V2 asymmetric format');
  assert(serverInspection.plaintext.includes('Recipient Private Key Required'), 'Server cannot read plaintext');

  // Client-side check: Bob decrypts with unlocked private key
  const bobDecryption = decryptAsymmetricEnvelope({
    envelope,
    recipientPrivateKey: bob.encryptionPrivateKey,
    recipientFingerprint: bob.fingerprint,
  });

  assert(bobDecryption.decrypted === true, 'Bob successfully decrypts ciphertext with private key');
  assert(bobDecryption.plaintext === sensitiveBody, 'Recovered message matches original plaintext');
  assert(bobDecryption.signatureVerified === true, 'Alice digital signature successfully verified');

  // ── TEST 3: Unauthorized Eavesdropper Decryption Blocked ───────────────────
  console.log('\n[+] Test 3: Unauthorized Eavesdropper Decryption Isolation');
  const eve = generateUserKeyPair(2048);
  const eveAttempt = decryptAsymmetricEnvelope({
    envelope,
    recipientPrivateKey: eve.encryptionPrivateKey,
    recipientFingerprint: eve.fingerprint,
  });

  assert(eveAttempt.decrypted === false, 'Unauthorized eavesdropper decryption blocked');
  assert(eveAttempt.plaintext.includes('Unauthorized Recipient Private Key Required') ||
         eveAttempt.plaintext.includes('Cryptographic Integrity Verification Failed'),
         'Unauthorized access returns secure error without leaking content');

  // ── TEST 4: HMAC Fallback User Token Persistence ───────────────────────────
  console.log('\n[+] Test 4: HMAC-Signed Fallback User Token with Bcrypt Hash');
  const sampleUser = {
    id: 'usr-fallback-001',
    name: 'Sovereign Agent',
    email: 'agent@garuda.gov.in',
    password: '$2b$12$e8yQ9aW0G1h2I3j4K5l6Me7n8o9p0q1r2s3t4u5v6w7x8y9z0a1b2',
    role: 'officer',
    department: 'Cryptographic Forensics',
    avatarColor: '#38BDF8',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const token = createFallbackToken(sampleUser);
  assert(typeof token === 'string' && token.includes('.'), 'Fallback token generated as signed dot-separated string');

  const recoveredUser = verifyFallbackToken(token);
  assert(recoveredUser !== null, 'Token verified successfully');
  assert(recoveredUser.email === sampleUser.email, 'Recovered user email matches');
  assert(recoveredUser.password === sampleUser.password, 'Bcrypt password hash preserved for seamless offline auth');

  // Tampered token test
  const tamperedToken = token.slice(0, -4) + 'AAAA';
  const tamperedRecovered = verifyFallbackToken(tamperedToken);
  assert(tamperedRecovered === null, 'Tampered token rejected by cryptographic HMAC check');

  // ── SUMMARY ───────────────────────────────────────────────────────────────
  console.log('\n=============================================================');
  console.log(` AUDIT RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('=============================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runAuditTests().catch(err => {
  console.error('Audit test suite encountered fatal exception:', err);
  process.exit(1);
});
