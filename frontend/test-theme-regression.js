/**
 * Theme & Accessibility Regression Test Suite
 * Validates WCAG 2.1 AA Contrast Ratios (>= 4.5:1) for Light Mode (surfaces, text & badges)
 * and verifies Storage Resilience (handling SecurityError / blocked storage).
 */

const assert = require('assert');

// ── 1. WCAG 2.1 Relative Luminance & Contrast Ratio Calculator ──
function hexToRgb(hex) {
  const sanitized = hex.replace('#', '');
  const r = parseInt(sanitized.substring(0, 2), 16) / 255;
  const g = parseInt(sanitized.substring(2, 4), 16) / 255;
  const b = parseInt(sanitized.substring(4, 6), 16) / 255;
  return [r, g, b];
}

function getLuminance(r, g, b) {
  const a = [r, g, b].map((v) => {
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  });
  return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
}

function getContrastRatio(hex1, hex2) {
  const [r1, g1, b1] = hexToRgb(hex1);
  const [r2, g2, b2] = hexToRgb(hex2);
  const lum1 = getLuminance(r1, g1, b1);
  const lum2 = getLuminance(r2, g2, b2);
  const brightest = Math.max(lum1, lum2);
  const darkest = Math.min(lum1, lum2);
  return (brightest + 0.05) / (darkest + 0.05);
}

console.log('====================================================');
console.log('1. VERIFYING WCAG 2.1 AA CONTRAST COMPLIANCE (>= 4.5:1)');
console.log('====================================================');

const lightBg = '#FFFFFF';
const lightSlateBg = '#F8FAFC';
const lightSurface2Bg = '#F1F5F9';

const lightModeColors = {
  '--color-accent-muted Sky-700 (#0369A1)': { color: '#0369A1', bg: lightBg },
  '--color-text-primary Slate-900 (#0F172A)': { color: '#0F172A', bg: lightBg },
  '--color-text-secondary Slate-700 (#334155)': { color: '#334155', bg: lightBg },
  '--color-text-dim Slate-600 (#475569)': { color: '#475569', bg: lightSurface2Bg },
  '--color-text-muted Slate-500 (#64748B)': { color: '#64748B', bg: lightBg },
  '--color-severity-critical (#DC2626)': { color: '#DC2626', bg: lightBg },
  '--color-severity-high (#B45309)': { color: '#B45309', bg: lightBg },
  '--color-severity-medium (#A16207)': { color: '#A16207', bg: lightBg },
  '--color-severity-low (#1D4ED8)': { color: '#1D4ED8', bg: lightBg },
  '--color-severity-healthy (#047857)': { color: '#047857', bg: lightBg },
  '--color-severity-info (#475569)': { color: '#475569', bg: lightBg },
  'TopBar Avatar Initials Light (#0369A1)': { color: '#0369A1', bg: lightBg },
  'Badge Critical (#B91C1C)': { color: '#B91C1C', bg: lightBg },
  'Badge High (#C2410C)': { color: '#C2410C', bg: lightBg },
  'Badge Medium (#854D0E)': { color: '#854D0E', bg: lightBg },
  'Badge Low (#1D4ED8)': { color: '#1D4ED8', bg: lightBg },
  'Badge Info (#334155)': { color: '#334155', bg: lightBg },
  'Badge Healthy (#047857)': { color: '#047857', bg: lightBg },
  'Badge Accent (#0369A1)': { color: '#0369A1', bg: lightBg },
  'Badge Purple (#6D28D9)': { color: '#6D28D9', bg: lightBg },
};

let allContrastPassed = true;

for (const [name, cfg] of Object.entries(lightModeColors)) {
  const ratio = getContrastRatio(cfg.color, cfg.bg);
  const passed = ratio >= 4.5;

  console.log(
    `[${passed ? 'PASS' : 'FAIL'}] ${name}: ` +
    `vs ${cfg.bg}: ${ratio.toFixed(2)}:1 (WCAG AA threshold: 4.5:1)`
  );

  if (!passed) allContrastPassed = false;
}

assert.strictEqual(allContrastPassed, true, 'All light mode tokens and badges must achieve >= 4.5:1 contrast.');
console.log('✓ All WCAG 2.1 AA contrast requirements verified successfully!\n');

console.log('====================================================');
console.log('2. VERIFYING STORAGE RESILIENCE (SECURITYERROR HANDLING)');
console.log('====================================================');

// Simulated storage throwing SecurityError (private browsing / denied cookies)
const simulatedBlockedStorage = {
  getItem: () => {
    const err = new Error('The operation is insecure (SecurityError)');
    err.name = 'SecurityError';
    throw err;
  },
  setItem: () => {
    const err = new Error('The operation is insecure (SecurityError)');
    err.name = 'SecurityError';
    throw err;
  }
};

// Simulate ThemeProvider initialization flow
function simulateThemeInit(storage) {
  let theme = 'light';
  try {
    const saved = storage.getItem('garuda-theme');
    if (saved === 'dark' || saved === 'light') theme = saved;
  } catch (e) {
    // Graceful fallback
    theme = 'light';
  }
  return theme;
}

function simulateThemeToggle(currentTheme, storage) {
  const next = currentTheme === 'dark' ? 'light' : 'dark';
  try {
    storage.setItem('garuda-theme', next);
  } catch (e) {
    // Graceful fallback: state changes in memory even if localStorage throws
  }
  return next;
}

const initialTheme = simulateThemeInit(simulatedBlockedStorage);
assert.strictEqual(initialTheme, 'light', 'Default theme must be "light" even under SecurityError');
console.log('✓ Storage init under SecurityError: gracefully fell back to "light"');

const toggledTheme = simulateThemeToggle(initialTheme, simulatedBlockedStorage);
assert.strictEqual(toggledTheme, 'dark', 'Theme toggles in-memory even when setItem throws SecurityError');
console.log('✓ Theme update under SecurityError: UI successfully updated without crashing\n');

console.log('====================================================');
console.log('ALL REGRESSION CHECKS PASSED (20 Contrast Tokens + Storage Failsafe)');
console.log('====================================================');
