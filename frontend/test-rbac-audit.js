/**
 * GARUDA Comprehensive RBAC, User Dashboard & Admin Control Plane Test Suite
 * Validates role-based authentication, dashboard redirection, account status enforcement,
 * privilege escalation prevention, user management workflows, and audit logging.
 */

const assert = require('assert');
const {
  findUserByEmail,
  verifyUserPassword,
  registerUser,
  updateUserStatus,
  updateUserRole,
  createAdminUser,
  listAllUsers,
  createFallbackToken,
  verifyFallbackToken
} = require('./src/lib/users');
const { getProtectedRouteForRole, normalizeUserRole, isAdmin } = require('./src/lib/roles');
const { getAuditLogs, logAuditEvent } = require('./src/lib/audit');

let passedChecks = 0;
let failedChecks = 0;

function assertPass(name, condition) {
  if (condition) {
    console.log(`  ✓ [PASS] ${name}`);
    passedChecks++;
  } else {
    console.error(`  ✗ [FAIL] ${name}`);
    failedChecks++;
  }
}

async function runRbacTestSuite() {
  console.log('\n=============================================================');
  console.log(' GARUDA ROLE-BASED ACCESS CONTROL & GOVERNANCE TEST SUITE');
  console.log('=============================================================\n');

  // ── TEST 1: Role Redirection Contracts ─────────────────────────────
  console.log('[+] Test 1: Role Redirection Contracts');
  assertPass('USER role maps to /user/dashboard', getProtectedRouteForRole('user') === '/user/dashboard');
  assertPass('ADMIN role maps to /admin/dashboard', getProtectedRouteForRole('admin') === '/admin/dashboard');
  assertPass('OFFICER role maps to /user/dashboard', getProtectedRouteForRole('officer') === '/user/dashboard');
  assertPass('isAdmin helper detects admin', isAdmin('admin') === true && isAdmin('user') === false);

  // ── TEST 2: Public Registration Privilege Escalation Prevention ─────
  console.log('\n[+] Test 2: Public Registration Privilege Escalation Prevention');
  const testUserEmail = `operative_${Date.now()}@test.internal`;
  const regResult = await registerUser('Tactical User', testUserEmail, 'SecurePass123!');
  
  assertPass('Public registration assigns role "user"', regResult.user.role === 'user');
  assertPass('Public registration assigns status "active"', regResult.user.status === 'active');
  assertPass('User cannot be admin upon public registration', regResult.user.role !== 'admin');

  // ── TEST 3: User Authentication & Credentials Verification ──────────
  console.log('\n[+] Test 3: User Authentication & Credentials Verification');
  const fetchedUser = await findUserByEmail(testUserEmail);
  assertPass('User found in credential directory', fetchedUser !== null);

  const validPass = await verifyUserPassword(fetchedUser, 'SecurePass123!');
  const invalidPass = await verifyUserPassword(fetchedUser, 'WrongPassword!');
  assertPass('Valid password verified successfully', validPass === true);
  assertPass('Invalid password safely rejected', invalidPass === false);

  // ── TEST 4: Account Suspension & Access Revocation ─────────────────
  console.log('\n[+] Test 4: Account Suspension & Access Revocation');
  const suspendResult = await updateUserStatus(testUserEmail, 'suspended', 'admin@garudamail.local');
  assertPass('Admin successfully suspended account', suspendResult.success === true);

  const suspendedUser = await findUserByEmail(testUserEmail);
  assertPass('Suspended account status persisted as "suspended"', suspendedUser.status === 'suspended');

  // ── TEST 5: Account Reactivation ───────────────────────────────────
  console.log('\n[+] Test 5: Account Reactivation');
  const reactivateResult = await updateUserStatus(testUserEmail, 'active', 'admin@garudamail.local');
  assertPass('Admin successfully reactivated account', reactivateResult.success === true);

  const activeUser = await findUserByEmail(testUserEmail);
  assertPass('Reactivated account status persisted as "active"', activeUser.status === 'active');

  // ── TEST 6: Administrative Role Promotion & Demotion ───────────────
  console.log('\n[+] Test 6: Administrative Role Promotion & Demotion');
  const promoteResult = await updateUserRole(testUserEmail, 'admin', 'admin@garudamail.local');
  assertPass('Admin promoted user to role "admin"', promoteResult.success === true);
  
  const promotedUser = await findUserByEmail(testUserEmail);
  assertPass('Promoted role verified as admin', promotedUser.role === 'admin');

  const demoteResult = await updateUserRole(testUserEmail, 'user', 'admin@garudamail.local');
  assertPass('Admin demoted user back to role "user"', demoteResult.success === true);

  const demotedUser = await findUserByEmail(testUserEmail);
  assertPass('Demoted role verified as user', demotedUser.role === 'user');

  // ── TEST 7: Protection Against Master Admin Tampering ──────────────
  console.log('\n[+] Test 7: Protection Against Master Admin Tampering');
  const masterSuspendAttempt = await updateUserStatus('admin@garudamail.local', 'suspended', 'admin@garudamail.local');
  assertPass('Suspending master admin is cryptographically blocked', masterSuspendAttempt.success === false);

  const masterDemoteAttempt = await updateUserRole('admin@garudamail.local', 'user', 'admin@garudamail.local');
  assertPass('Demoting master admin is cryptographically blocked', masterDemoteAttempt.success === false);

  // ── TEST 8: Audit Logging & Governance Ledger ──────────────────────
  console.log('\n[+] Test 8: Audit Logging & Governance Ledger');
  const logs = await getAuditLogs(50);
  assertPass('Audit logs populated and readable', Array.isArray(logs) && logs.length > 0);

  const hasSuspensionAudit = logs.some(l => l.action === 'ACCOUNT_SUSPENDED' && l.targetEmail === testUserEmail);
  const hasReactivationAudit = logs.some(l => l.action === 'ACCOUNT_ACTIVATED' && l.targetEmail === testUserEmail);
  const hasRoleAudit = logs.some(l => l.action === 'ROLE_CHANGED' && l.targetEmail === testUserEmail);

  assertPass('Audit log contains account suspension record', hasSuspensionAudit === true);
  assertPass('Audit log contains account reactivation record', hasReactivationAudit === true);
  assertPass('Audit log contains role modification record', hasRoleAudit === true);

  // ── FINAL SUMMARY ──────────────────────────────────────────────────
  console.log('\n=============================================================');
  console.log(` RBAC SUITE RESULTS: ${passedChecks} PASSED, ${failedChecks} FAILED`);
  console.log('=============================================================\n');

  if (failedChecks > 0) {
    process.exit(1);
  }
}

runRbacTestSuite().catch(err => {
  console.error('[!] RBAC Test Suite Exception:', err);
  process.exit(1);
});
