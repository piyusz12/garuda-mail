#!/usr/bin/env node

/**
 * GARUDA Administrator Secure Provisioning Script
 * Usage: npx tsx scripts/bootstrap-admin.js <email> <password> [name]
 */

const path = require('path');
const { createAdminUser } = require('../src/lib/users');

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.error('Error: Insufficient arguments.');
    console.log('Usage: npx tsx scripts/bootstrap-admin.js <email> <password> [name]');
    process.exit(1);
  }

  const email = args[0].toLowerCase().trim();
  const password = args[1];
  const name = args[2] || 'System Administrator';

  if (!email.includes('@')) {
    console.error('Error: Invalid email format.');
    process.exit(1);
  }

  if (password.length < 8) {
    console.error('Error: Administrator password must be at least 8 characters.');
    process.exit(1);
  }

  try {
    const admin = await createAdminUser(name, email, password, 'bootstrap-cli');
    console.log('\n=============================================================');
    console.log(' GARUDA SECURE ADMINISTRATOR PROVISIONING');
    console.log('=============================================================');
    console.log(` [+] Admin Account:    ${admin.email}`);
    console.log(` [+] Display Name:     ${admin.name}`);
    console.log(` [+] Assigned Role:    ${admin.role.toUpperCase()}`);
    console.log(` [+] Account Status:   ${admin.status.toUpperCase()}`);
    console.log(` [+] Audit Event:      ADMIN_PROVISIONED (Recorded to immutable ledger)`);
    console.log('=============================================================\n');
    process.exit(0);
  } catch (err) {
    console.error('[!] Failed to provision administrator:', err);
    process.exit(1);
  }
}

main();
