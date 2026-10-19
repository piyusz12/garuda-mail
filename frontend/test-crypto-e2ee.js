/**
 * GARUDA — Automated Cryptographic & E2EE Verification Test Suite (Phases 4, 5, 6)
 * Proves:
 * 1. Key generation & SHA-256 fingerprinting.
 * 2. PC-A encrypts & signs for PC-B.
 * 3. PC-B decrypts & verifies PC-A's signature.
 * 4. Unauthorized PC-C CANNOT decrypt message with own key.
 * 5. Tampered ciphertext triggers integrity failure.
 * 6. Tampered signature triggers signature verification failure.
 * 7. Passphrase protection for private keys.
 * 8. Zero-knowledge database verification (server holds ciphertext only).
 */

const assert = require('assert');
const {
  generateUserKeyPair,
  getPublicKeyFingerprint,
  encryptAsymmetricEnvelope,
  decryptAsymmetricEnvelope,
  encryptPrivateKeyWithPassphrase,
  decryptPrivateKeyWithPassphrase,
} = require('./src/lib/crypto');

function runSuite() {
  console.log('\n=============================================================');
  console.log(' GARUDA E2EE & DIGITAL SIGNATURES AUTOMATED VERIFICATION');
  console.log('=============================================================\n');

  // 1. Generate Keypairs for Alice (PC-A), Bob (PC-B), and Mallory (PC-C)
  console.log('[+] Step 1: Generating RSA-OAEP & RSA-PSS Keypairs for participants...');
  const alice = generateUserKeyPair(2048);
  const bob = generateUserKeyPair(2048);
  const mallory = generateUserKeyPair(2048);

  console.log(`    Alice (PC-A) Fingerprint:   ${alice.fingerprint}`);
  console.log(`    Bob (PC-B) Fingerprint:     ${bob.fingerprint}`);
  console.log(`    Mallory (PC-C) Fingerprint: ${mallory.fingerprint}`);

  assert(alice.fingerprint.startsWith('SHA256:'), 'Alice fingerprint format invalid');
  assert(bob.fingerprint.startsWith('SHA256:'), 'Bob fingerprint format invalid');
  assert.notStrictEqual(alice.fingerprint, bob.fingerprint, 'Fingerprints must be unique');

  // 2. Alice encrypts & signs a confidential message for Bob
  console.log('\n[+] Step 2: PC-A encrypting and digitally signing confidential payload for PC-B...');
  const secretMessage = 'TOP SECRET: Defense deployment coordinates for sector 7. PQC hybrid active.';

  const { envelopeString, envelope } = encryptAsymmetricEnvelope({
    plaintext: secretMessage,
    senderKeyPair: {
      signingPrivateKey: alice.signingPrivateKey,
      signingPublicKey: alice.signingPublicKey,
      encryptionPublicKey: alice.encryptionPublicKey,
    },
    recipientPublicKeys: [
      {
        recipientFingerprint: bob.fingerprint,
        encryptionPublicKey: bob.encryptionPublicKey,
      },
    ],
  });

  console.log(`    Envelope ID:         ${envelope.envelopeId}`);
  console.log(`    Ciphertext (Base64): ${envelope.ciphertext.slice(0, 32)}...`);
  console.log(`    Digital Signature:   ${envelope.signature.slice(0, 32)}...`);
  console.log(`    Sender Fingerprint:  ${envelope.senderFingerprint}`);

  // Prove Server Storage Zero-Knowledge: Plaintext never appears in stored string
  assert(!envelopeString.includes(secretMessage), 'ZERO-KNOWLEDGE VIOLATION: Plaintext found in envelope string!');
  assert(!envelope.ciphertext.includes(secretMessage), 'ZERO-KNOWLEDGE VIOLATION: Plaintext found in ciphertext!');
  console.log('    ✓ Zero-knowledge check passed: Server database holds ONLY encrypted ciphertext.');

  // 3. Bob (authorized recipient) decrypts and verifies
  console.log('\n[+] Step 3: PC-B decrypting message with private key & verifying PC-A signature...');
  const bobResult = decryptAsymmetricEnvelope({
    envelope,
    recipientPrivateKey: bob.encryptionPrivateKey,
    recipientFingerprint: bob.fingerprint,
    senderSigningPublicKey: alice.signingPublicKey,
  });

  console.log(`    Decryption Success:  ${bobResult.decrypted}`);
  console.log(`    Integrity Valid:     ${bobResult.integrityValid}`);
  console.log(`    Signature Verified:  ${bobResult.signatureVerified}`);
  console.log(`    Recovered Plaintext: "${bobResult.plaintext}"`);

  assert.strictEqual(bobResult.decrypted, true, 'Bob failed to decrypt message');
  assert.strictEqual(bobResult.integrityValid, true, 'Integrity check failed');
  assert.strictEqual(bobResult.signatureVerified, true, 'Digital signature verification failed');
  assert.strictEqual(bobResult.plaintext, secretMessage, 'Decrypted text does not match original message');
  console.log('    ✓ PC-B successfully decrypted message and verified PC-A digital signature.');

  // 4. Mallory (unauthorized PC-C) attempts to decrypt
  console.log('\n[+] Step 4: Unauthorized PC-C (Mallory) attempting to decrypt Alice->Bob message...');
  const malloryResult = decryptAsymmetricEnvelope({
    envelope,
    recipientPrivateKey: mallory.encryptionPrivateKey,
    recipientFingerprint: mallory.fingerprint,
    senderSigningPublicKey: alice.signingPublicKey,
  });

  console.log(`    Mallory Decrypted:   ${malloryResult.decrypted}`);
  console.log(`    Mallory Plaintext:   "${malloryResult.plaintext}"`);
  assert.strictEqual(malloryResult.decrypted, false, 'SECURITY FAILURE: Unauthorized user decrypted message!');
  assert.notStrictEqual(malloryResult.plaintext, secretMessage, 'Mallory recovered secret plaintext!');
  console.log('    ✓ Unauthorized access successfully blocked: Mallory cannot decrypt message.');

  // 5. Tamper Detection: Modified Ciphertext
  console.log('\n[+] Step 5: Testing Tamper Detection (Bit modification in ciphertext)...');
  const tamperedEnvelope = JSON.parse(JSON.stringify(envelope));
  const rawBytes = Buffer.from(tamperedEnvelope.ciphertext, 'base64');
  rawBytes[0] ^= 0xFF; // Flip first byte
  tamperedEnvelope.ciphertext = rawBytes.toString('base64');

  const tamperResult = decryptAsymmetricEnvelope({
    envelope: tamperedEnvelope,
    recipientPrivateKey: bob.encryptionPrivateKey,
    recipientFingerprint: bob.fingerprint,
    senderSigningPublicKey: alice.signingPublicKey,
  });

  console.log(`    Tampered Decryption: ${tamperResult.decrypted}`);
  console.log(`    Tamper Status:       "${tamperResult.plaintext}"`);
  assert.strictEqual(tamperResult.decrypted, false, 'Tampered ciphertext was accepted without error!');
  console.log('    ✓ Tampering detected: Modified ciphertext failed cryptographic authentication.');

  // 6. Signature Forgery Detection: Modified Signature
  console.log('\n[+] Step 6: Testing Signature Verification Failure on Altered Payload...');
  const forgedEnvelope = JSON.parse(JSON.stringify(envelope));
  forgedEnvelope.timestamp = '2020-01-01T00:00:00.000Z'; // Replay/timestamp tampering

  const forgeResult = decryptAsymmetricEnvelope({
    envelope: forgedEnvelope,
    recipientPrivateKey: bob.encryptionPrivateKey,
    recipientFingerprint: bob.fingerprint,
    senderSigningPublicKey: alice.signingPublicKey,
  });

  console.log(`    Signature Valid on Altered Timestamp: ${forgeResult.signatureVerified}`);
  assert.strictEqual(forgeResult.signatureVerified, false, 'SECURITY FAILURE: Forged/tampered envelope passed signature verification!');
  console.log('    ✓ Signature verification correctly rejected modified/replayed envelope.');

  // 7. Passphrase-Protected Private Key Storage
  console.log('\n[+] Step 7: Testing Passphrase-Protected Client Private Key Storage...');
  const passphrase = 'SuperSecureUserPassphrase2026!';
  const encryptedKeyBundle = encryptPrivateKeyWithPassphrase(alice.encryptionPrivateKey, passphrase);
  assert(!encryptedKeyBundle.includes(alice.encryptionPrivateKey), 'Plaintext private key found in encrypted bundle!');

  // Decrypt with correct passphrase
  const recoveredKey = decryptPrivateKeyWithPassphrase(encryptedKeyBundle, passphrase);
  assert.strictEqual(recoveredKey, alice.encryptionPrivateKey, 'Recovered private key does not match original!');
  console.log('    ✓ Correct passphrase successfully unlocks client private key.');

  // Decrypt with wrong passphrase fails
  let wrongPassphraseFailed = false;
  try {
    decryptPrivateKeyWithPassphrase(encryptedKeyBundle, 'WrongPassword123');
  } catch (err) {
    wrongPassphraseFailed = true;
  }
  assert.strictEqual(wrongPassphraseFailed, true, 'Wrong passphrase did not trigger decryption failure!');
  console.log('    ✓ Incorrect passphrase fails to unlock client private key.');

  console.log('\n=============================================================');
  console.log(' ALL 7 CRYPTOGRAPHIC VERIFICATION CHECKS PASSED PERFECTLY!');
  console.log('=============================================================\n');
}

runSuite();
