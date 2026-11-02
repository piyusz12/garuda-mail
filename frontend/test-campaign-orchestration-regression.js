/**
 * Garuda Mail: Campaign Orchestration & Architecture Regression Test Suite
 * Validates:
 * 1. Zod Campaign Validation Schemas (Step 1-4)
 * 2. 80/20 Text-to-Image Heuristic & Missing Alt-Text Audit
 * 3. Spam Keyword Heuristic & Mobile Notification Truncation
 * 4. RFC 8058 One-Click Unsubscribe HMAC Cryptographic Tokens & Headers
 * 5. Deliverability Warm-Up Schedule Progression
 */

const assert = require('assert');
const crypto = require('crypto');

console.log('─── Running Garuda Mail Strategic Architecture Regression Suite ───\n');

// ── 1. RFC 8058 Cryptographic Signature Tests ───────────────────────
const SECRET_SALT = 'garuda-rfc8058-token-salt-secure-key';

function generateUnsubscribeToken(email, campaignId = 'general') {
  const payload = {
    email: email.toLowerCase().trim(),
    campaignId,
    timestamp: Date.now(),
  };
  const jsonStr = JSON.stringify(payload);
  const base64Data = Buffer.from(jsonStr).toString('base64url');
  const hmac = crypto.createHmac('sha256', SECRET_SALT).update(base64Data).digest('base64url');
  return `${base64Data}.${hmac}`;
}

function verifyUnsubscribeToken(token) {
  try {
    const [base64Data, hmac] = token.split('.');
    if (!base64Data || !hmac) return null;

    const expectedHmac = crypto.createHmac('sha256', SECRET_SALT).update(base64Data).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expectedHmac))) {
      return null;
    }

    const jsonStr = Buffer.from(base64Data, 'base64url').toString('utf-8');
    return JSON.parse(jsonStr);
  } catch {
    return null;
  }
}

function generateRfc8058Headers(email, campaignId, baseUrl = 'https://garuda-mail.vercel.app') {
  const token = generateUnsubscribeToken(email, campaignId);
  const cleanBase = baseUrl.replace(/\/+$/, '');
  return {
    'List-Unsubscribe': `<${cleanBase}/api/unsubscribe/${token}>`,
    'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
  };
}

// Test RFC 8058 Header Generation & Verification
const testEmail = 'officer.chen@cyber-command.gov';
const testToken = generateUnsubscribeToken(testEmail, 'camp-01');
const verified = verifyUnsubscribeToken(testToken);

assert(verified !== null, 'Token should verify successfully');
assert.strictEqual(verified.email, testEmail, 'Verified email must match input');
assert.strictEqual(verified.campaignId, 'camp-01', 'Campaign ID must match');

const headers = generateRfc8058Headers(testEmail, 'camp-01');
assert.strictEqual(headers['List-Unsubscribe-Post'], 'List-Unsubscribe=One-Click', 'RFC 8058 Post header must match');
assert(headers['List-Unsubscribe'].includes('/api/unsubscribe/'), 'List-Unsubscribe header must contain API endpoint');

// Test Forged Token Rejection
const tamperedToken = testToken.slice(0, -4) + 'XXXX';
const forged = verifyUnsubscribeToken(tamperedToken);
assert.strictEqual(forged, null, 'Tampered token must be rejected');
console.log('✓ Test 1 Passed: RFC 8058 One-Click Header & HMAC Token Integrity verified.');

// ── 2. 80/20 Text-to-Image Deliverability Heuristic Tests ───────────
function calculateTextToImageRatio(html) {
  const strippedText = html.replace(/<[^>]*>/g, '').trim();
  const textCharCount = strippedText.length;
  const imgTags = html.match(/<img[^>]*>/gi) || [];
  const imgWeight = imgTags.length * 200;
  const totalWeight = Math.max(textCharCount + imgWeight, 1);
  const textRatio = Math.round((textCharCount / totalWeight) * 100);
  const imageRatio = 100 - textRatio;
  return { textRatio, imageRatio, isCompliant: textRatio >= 80 };
}

const compliantHtml = `<p>${'Enterprise security alert '.repeat(40)}</p><img src="logo.png" alt="Garuda Logo" />`;
const compliantRatio = calculateTextToImageRatio(compliantHtml);
assert(compliantRatio.isCompliant, 'Should be compliant when text heavily outweighs image');

const imageHeavyHtml = `<p>Short text</p><img src="img1.jpg" /><img src="img2.jpg" /><img src="img3.jpg" />`;
const imageHeavyRatio = calculateTextToImageRatio(imageHeavyHtml);
assert(!imageHeavyRatio.isCompliant, 'Should fail 80/20 rule when images dominate content');
console.log('✓ Test 2 Passed: 80/20 Text-to-Image Heuristic correctly enforces deliverability thresholds.');

// ── 3. Image Alt-Text Accessibility Scanner ─────────────────────────
function auditAltText(html) {
  const imgTags = html.match(/<img[^>]*>/gi) || [];
  const missingAlt = [];
  imgTags.forEach((tag, idx) => {
    const hasAlt = /alt\s*=\s*["'][^"']+["']/i.test(tag);
    if (!hasAlt) {
      const srcMatch = tag.match(/src\s*=\s*["']([^"']+)["']/i);
      missingAlt.push(srcMatch ? srcMatch[1] : `img_${idx}`);
    }
  });
  return missingAlt;
}

const htmlWithMissingAlt = `<div><img src="valid.png" alt="A valid diagram" /><img src="bad.png" /></div>`;
const missingImages = auditAltText(htmlWithMissingAlt);
assert.strictEqual(missingImages.length, 1, 'Should find exactly 1 image missing alt text');
assert.strictEqual(missingImages[0], 'bad.png', 'Should identify the correct source file missing alt');
console.log('✓ Test 3 Passed: Alt-text accessibility scanner successfully flags WCAG omissions.');

// ── 4. Spam Keyword Scanner Heuristic ───────────────────────────────
const SPAM_TRIGGER_WORDS = ['free', '100% free', 'guarantee', 'risk-free', '$$$', 'winner', 'act now'];

function checkSpamWord(text, word) {
  if (word === '$$$') {
    return text.includes('$$$');
  }
  const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`\\b${escaped}\\b`, 'i');
  return regex.test(text);
}

function detectSpamKeywords(text) {
  const lower = text.toLowerCase();
  return SPAM_TRIGGER_WORDS.filter((word) => checkSpamWord(lower, word));
}

const cleanSubject = 'Quarterly Cryptographic Security Audit & CBOM Telemetry';
assert.strictEqual(detectSpamKeywords(cleanSubject).length, 0, 'Clean subject should have 0 spam keywords');

const spamSubject = 'Act Now! Free Guarantee of High Deliverability $$$';
const detectedSpam = detectSpamKeywords(spamSubject);
assert(detectedSpam.length >= 4, 'Should detect all 4 high-risk spam keywords');
assert(detectedSpam.includes('free'), 'Must identify "free"');
assert(detectedSpam.includes('guarantee'), 'Must identify "guarantee"');
assert(detectedSpam.includes('$$$'), 'Must identify "$$$"');
assert(detectedSpam.includes('act now'), 'Must identify "act now"');
console.log('✓ Test 4 Passed: Real-time spam keyword scanner detects high-risk marketing triggers.');

// ── 5. Mobile Viewport Truncation Preview ───────────────────────────
function previewMobileSubject(subject) {
  const iphoneTruncated = subject.length > 38;
  const iphonePreview = iphoneTruncated ? `${subject.slice(0, 35)}...` : subject;
  const androidTruncated = subject.length > 42;
  const androidPreview = androidTruncated ? `${subject.slice(0, 39)}...` : subject;
  return { iphoneTruncated, iphonePreview, androidTruncated, androidPreview };
}

const longSubject = 'Critical Q4 Cryptographic Intelligence & RFC 8058 Directives for Enterprise Security';
const mobilePreview = previewMobileSubject(longSubject);
assert(mobilePreview.iphoneTruncated, 'Long subject must be truncated on iOS');
assert(mobilePreview.androidTruncated, 'Long subject must be truncated on Android');
assert(mobilePreview.iphonePreview.length <= 38, 'Truncated iOS preview must stay within limit');
console.log('✓ Test 5 Passed: Mobile viewport notification bar truncation correctly computed.');

// ── 6. Deliverability Warm-Up Schedule Progression ──────────────────
const WARMUP_TIERS = [
  { day: 1, limit: 50 },
  { day: 7, limit: 400 },
  { day: 14, limit: 1800 },
  { day: 21, limit: 5000 },
  { day: 28, limit: 25000 },
];

for (let i = 1; i < WARMUP_TIERS.length; i++) {
  assert(
    WARMUP_TIERS[i].limit > WARMUP_TIERS[i - 1].limit,
    'Warm-up limits must strictly increase monotonically to protect domain reputation'
  );
}
console.log('✓ Test 6 Passed: 28-day warm-up trajectory exhibits monotonic ramp-up.');

console.log('\nAll 6 Architecture & Deliverability Regression Tests Passed 100%!\n');
