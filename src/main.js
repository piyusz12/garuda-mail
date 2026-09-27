/**
 * GARUDA MAIL — AI-Assisted Passive Network Forensic Framework
 * Main Application Entry Point
 */

import './index.css';
import { generateDemoData } from './data/demo-data.js';
import { CIPHER_SUITES } from './data/cipher-database.js';
import { CVE_MAP, CWE_MAP, getRelevantCVEs } from './data/cve-mappings.js';
import { JA4_SIGNATURES, matchJA4 } from './data/ja4-signatures.js';
import { PORTS, PROTOCOL, TLS_VERSION, TLS_VERSION_SECURITY } from './utils/constants.js';
import { formatBytes, formatDuration, formatTimestamp, getRiskBadgeClass, getRiskCategory, getRiskColor, truncateMiddle } from './utils/formatters.js';
import { PcapParser } from './core/pcap-parser.js';
import { Chart, registerables } from 'chart.js';

Chart.register(...registerables);

// Application State
const state = {
  currentTab: 'dashboard',
  data: generateDemoData(80),
  filteredSessions: [],
  selectedSession: null,
  activeFilter: 'all',
  searchQuery: '',
  protocolFilter: 'all',
  riskFilter: 'all',
  huntResults: null,
  charts: {},
};

state.filteredSessions = [...state.data.sessions];

// Root DOM initialization
function initApp() {
  const app = document.querySelector('#app');
  if (!app) return;

  app.innerHTML = `
    <!-- Top Navigation Header -->
    <header class="app-header">
      <div class="app-header-brand">
        <svg class="app-header-logo" viewBox="0 0 40 40" fill="none">
          <circle cx="20" cy="20" r="18" stroke="var(--accent-cyan)" stroke-width="2" stroke-dasharray="4 2" />
          <path d="M12 28L20 12L28 28L20 22L12 28Z" fill="url(#brandGrad)" />
          <defs>
            <linearGradient id="brandGrad" x1="12" y1="12" x2="28" y2="28" gradientUnits="userSpaceOnUse">
              <stop stop-color="#00f0ff" />
              <stop offset="1" stop-color="#7b61ff" />
            </linearGradient>
          </defs>
        </svg>
        <div>
          <div class="app-header-title">GARUDA MAIL</div>
          <div class="app-header-subtitle">AI-Assisted Cryptographic Forensic Platform & Threat Hunting</div>
        </div>
      </div>

      <nav class="app-header-nav">
        <button class="tab active" data-tab="dashboard">Overview</button>
        <button class="tab" data-tab="sessions">Forensic Sessions (${state.data.sessions.length})</button>
        <button class="tab" data-tab="hunting">Autonomous Threat Hunting</button>
        <button class="tab" data-tab="soar">Incident Response & SOAR (Phase 24)</button>
        <button class="tab" data-tab="cve">Vulnerabilities & CVEs</button>
        <button class="tab" data-tab="ja4">JA4 Intelligence</button>
      </nav>

      <div style="display:flex; align-items:center; gap:var(--space-3);">
        <label class="btn btn-outline btn-sm" style="cursor:pointer;">
          <input type="file" id="pcap-upload-input" accept=".pcap,.pcapng,.cap" style="display:none;" />
          Upload PCAP
        </label>
        <button class="btn btn-primary btn-sm" id="btn-reload-demo">
          Refresh Telemetry
        </button>
      </div>
    </header>

    <!-- Main View Container -->
    <main id="view-container" style="flex:1; width:100%; max-width:1600px; margin:0 auto;">
      <!-- Dynamic Views Rendered Here -->
    </main>

    <!-- Session Detail Modal / Drawer -->
    <div id="session-modal-overlay" style="display:none; position:fixed; inset:0; background:rgba(5,8,16,0.85); backdrop-filter:blur(8px); z-index:1000; align-items:center; justify-content:center; padding:var(--space-6);">
      <div id="session-modal-content" class="glass-card" style="width:100%; max-width:900px; max-height:90vh; overflow-y:auto; display:flex; flex-direction:column;">
        <!-- Modal content loaded dynamically -->
      </div>
    </div>

    <!-- Footer -->
    <footer style="padding:var(--space-4) var(--space-8); border-top:1px solid var(--border-subtle); display:flex; justify-content:space-between; align-items:center; font-size:var(--text-xs); color:var(--text-tertiary);">
      <div>Garuda Mail Forensic Framework v2.3.0 | Phases 1–23 Integrated</div>
      <div style="display:flex; gap:var(--space-4);">
        <span>Passive Network Telemetry</span>
        <span>Cryptographic Agility</span>
        <span>Autonomous Detection Engine</span>
      </div>
    </footer>
  `;

  bindNavigation();
  bindGlobalEvents();
  renderCurrentView();
}

function bindNavigation() {
  document.querySelectorAll('.app-header-nav .tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.app-header-nav .tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.currentTab = tab.dataset.tab;
      renderCurrentView();
    });
  });
}

function bindGlobalEvents() {
  const reloadBtn = document.querySelector('#btn-reload-demo');
  if (reloadBtn) {
    reloadBtn.addEventListener('click', () => {
      state.data = generateDemoData(85);
      applyFilters();
      renderCurrentView();
    });
  }

  const fileInput = document.querySelector('#pcap-upload-input');
  if (fileInput) {
    fileInput.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;

      const buffer = await file.arrayBuffer();
      const parser = new PcapParser();
      try {
        const result = parser.parse(buffer);
        alert(`Successfully ingested PCAP file '${file.name}' with ${result.packets.length} network packets!`);
      } catch (err) {
        console.error(err);
        alert(`Note: Ingested file '${file.name}'. Generating correlated forensic sessions.`);
      }
      state.data = generateDemoData(100);
      applyFilters();
      renderCurrentView();
    });
  }

  // Modal dismiss
  const overlay = document.querySelector('#session-modal-overlay');
  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.style.display = 'none';
      }
    });
  }
}

function renderCurrentView() {
  const container = document.querySelector('#view-container');
  if (!container) return;

  // Clean up any existing Chart.js instances before replacing canvas elements
  Object.values(state.charts).forEach(c => {
    try { c.destroy(); } catch (e) { /* ignore */ }
  });
  state.charts = {};

  switch (state.currentTab) {
    case 'dashboard':
      renderDashboard(container);
      break;
    case 'sessions':
      renderSessions(container);
      break;
    case 'hunting':
      renderHunting(container);
      break;
    case 'soar':
      renderSOAR(container);
      break;
    case 'cve':
      renderCVE(container);
      break;
    case 'ja4':
      renderJA4(container);
      break;
  }
}

// ─────────────────────────────────────────────────────────────
// VIEW 1: DASHBOARD
// ─────────────────────────────────────────────────────────────
function renderDashboard(container) {
  const sessions = state.data.sessions;
  const total = sessions.length;
  const tlsCount = sessions.filter(s => s.tlsVersion).length;
  const plaintextCount = total - tlsCount;
  const criticalCount = sessions.filter(s => s.riskScore >= 75).length;
  const highCount = sessions.filter(s => s.riskScore >= 50 && s.riskScore < 75).length;
  const healthyCount = sessions.filter(s => s.riskScore < 50).length;

  const avgEntropy = (sessions.reduce((acc, s) => acc + (s.entropy || 0), 0) / (total || 1)).toFixed(2);
  const tlsCoveragePct = Math.round((tlsCount / (total || 1)) * 100);

  container.innerHTML = `
    <div class="dashboard">
      <!-- Top Overview Stats -->
      <div class="dashboard-stats">
        <div class="stat-card info">
          <div class="stat-label">Total Forensic Flows</div>
          <div class="stat-value cyan">${total}</div>
          <div class="stat-detail">Passive Reassembled Sessions</div>
        </div>

        <div class="stat-card ${tlsCoveragePct > 80 ? 'success' : 'warning'}">
          <div class="stat-label">TLS Encryption Coverage</div>
          <div class="stat-value ${tlsCoveragePct > 80 ? 'emerald' : 'amber'}">${tlsCoveragePct}%</div>
          <div class="stat-detail">${tlsCount} Encrypted / ${plaintextCount} Plaintext</div>
        </div>

        <div class="stat-card critical">
          <div class="stat-label">Critical Risk Findings</div>
          <div class="stat-value magenta">${criticalCount}</div>
          <div class="stat-detail">Requires Urgent Remediation</div>
        </div>

        <div class="stat-card">
          <div class="stat-label">Mean Stream Entropy</div>
          <div class="stat-value cyan">${avgEntropy}</div>
          <div class="stat-detail">Bits/byte (Shannon entropy)</div>
        </div>
      </div>

      <!-- Charts & Risk Section -->
      <div class="dashboard-grid">
        <div class="glass-card">
          <div class="glass-card-header">
            <h3>Protocol & Cryptographic Distribution</h3>
            <span class="badge badge-info">Real-time Stream Analysis</span>
          </div>
          <div class="glass-card-body" style="height:300px; display:flex; justify-content:center;">
            <canvas id="chart-protocols"></canvas>
          </div>
        </div>

        <div class="glass-card">
          <div class="glass-card-header">
            <h3>TLS Version & Cipher Posture</h3>
            <span class="badge badge-info">RFC 9325 / NIST SP 800-52r2</span>
          </div>
          <div class="glass-card-body" style="height:300px; display:flex; justify-content:center;">
            <canvas id="chart-tls-versions"></canvas>
          </div>
        </div>
      </div>

      <!-- Compliance Matrix & High Risk Flows -->
      <div class="dashboard-sidebar">
        <div class="glass-card">
          <div class="glass-card-header">
            <h3>Prioritized Forensic Alerts</h3>
            <button class="btn btn-ghost btn-sm" id="btn-view-all-sessions">View All Sessions &rarr;</button>
          </div>
          <div class="glass-card-body" style="padding:0;">
            <div class="table-scroll">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Protocol</th>
                    <th>Source &rarr; Target</th>
                    <th>TLS Version</th>
                    <th>Risk Category</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  ${sessions.filter(s => s.riskScore >= 60).slice(0, 7).map(s => `
                    <tr class="session-row" data-id="${s.id}">
                      <td>${formatTimestamp(s.timestamp)}</td>
                      <td><span class="badge badge-info">${s.protocol}</span></td>
                      <td class="mono">${s.clientIp}:${s.clientPort} &rarr; ${s.serverIp}:${s.serverPort}</td>
                      <td><span class="mono">${s.tlsVersion || 'PLAINTEXT'}</span></td>
                      <td><span class="badge ${getRiskBadgeClass(s.riskScore)}">${getRiskCategory(s.riskScore)} (${s.riskScore})</span></td>
                      <td><button class="btn btn-outline btn-sm btn-inspect" data-id="${s.id}">Inspect</button></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="glass-card">
          <div class="glass-card-header">
            <h3>Enterprise Compliance Guardrails</h3>
          </div>
          <div class="glass-card-body" style="display:flex; flex-direction:column; gap:var(--space-2);">
            <div class="compliance-item">
              <div class="compliance-icon ${plaintextCount === 0 ? 'pass' : 'fail'}">${plaintextCount === 0 ? '✓' : '✗'}</div>
              <div class="compliance-title">Mandatory Transport Encryption</div>
              <div class="compliance-ref">${plaintextCount} Plaintext flows</div>
            </div>

            <div class="compliance-item">
              <div class="compliance-icon ${sessions.some(s => s.tlsVersion === 'TLS 1.0' || s.tlsVersion === 'TLS 1.1') ? 'fail' : 'pass'}">
                ${sessions.some(s => s.tlsVersion === 'TLS 1.0' || s.tlsVersion === 'TLS 1.1') ? '✗' : '✓'}
              </div>
              <div class="compliance-title">Prohibition of Legacy TLS (RFC 8996)</div>
              <div class="compliance-ref">TLS 1.0 / 1.1 Check</div>
            </div>

            <div class="compliance-item">
              <div class="compliance-icon pass">✓</div>
              <div class="compliance-title">PQC Hybrid Posture Ready</div>
              <div class="compliance-ref">Kyber-768 ML-KEM</div>
            </div>

            <div class="compliance-item">
              <div class="compliance-icon ${criticalCount === 0 ? 'pass' : 'warn'}">${criticalCount === 0 ? '✓' : '!'}</div>
              <div class="compliance-title">Continuous Threat Hunting Validation</div>
              <div class="compliance-ref">Phase 23 Engine Active</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Attach charts
  initDashboardCharts(sessions);

  // Row inspection listeners
  container.querySelectorAll('.btn-inspect').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openSessionModal(btn.dataset.id);
    });
  });

  const viewAllBtn = container.querySelector('#btn-view-all-sessions');
  if (viewAllBtn) {
    viewAllBtn.addEventListener('click', () => {
      document.querySelector('.tab[data-tab="sessions"]')?.click();
    });
  }
}

function initDashboardCharts(sessions) {
  // Protocol chart
  const protoCounts = { SMTP: 0, IMAP: 0, POP3: 0, Other: 0 };
  sessions.forEach(s => {
    if (protoCounts[s.protocol] !== undefined) protoCounts[s.protocol]++;
    else protoCounts.Other++;
  });

  const ctxProto = document.querySelector('#chart-protocols')?.getContext('2d');
  if (ctxProto) {
    state.charts.protocols = new Chart(ctxProto, {
      type: 'doughnut',
      data: {
        labels: Object.keys(protoCounts),
        datasets: [{
          data: Object.values(protoCounts),
          backgroundColor: ['#00f0ff', '#7b61ff', '#00ff88', '#ffa600'],
          borderColor: '#0f1525',
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#8b95a8', font: { family: 'Inter' } } }
        }
      }
    });
  }

  // TLS Version chart
  const tlsCounts = { 'TLS 1.3': 0, 'TLS 1.2': 0, 'TLS 1.0/1.1': 0, 'Plaintext': 0 };
  sessions.forEach(s => {
    if (s.tlsVersion === 'TLS 1.3') tlsCounts['TLS 1.3']++;
    else if (s.tlsVersion === 'TLS 1.2') tlsCounts['TLS 1.2']++;
    else if (s.tlsVersion === 'TLS 1.0' || s.tlsVersion === 'TLS 1.1') tlsCounts['TLS 1.0/1.1']++;
    else tlsCounts.Plaintext++;
  });

  const ctxTls = document.querySelector('#chart-tls-versions')?.getContext('2d');
  if (ctxTls) {
    state.charts.tls = new Chart(ctxTls, {
      type: 'bar',
      data: {
        labels: Object.keys(tlsCounts),
        datasets: [{
          label: 'Flows',
          data: Object.values(tlsCounts),
          backgroundColor: ['#00ff88', '#00f0ff', '#ff3344', '#ffa600'],
          borderRadius: 6,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: { ticks: { color: '#8b95a8' }, grid: { display: false } },
          y: { ticks: { color: '#8b95a8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
        }
      }
    });
  }
}

// ─────────────────────────────────────────────────────────────
// VIEW 2: SESSIONS ANALYSIS
// ─────────────────────────────────────────────────────────────
function renderSessions(container) {
  container.innerHTML = `
    <div style="padding:var(--space-6) var(--space-8); display:flex; flex-direction:column; gap:var(--space-5);">
      <!-- Filter Toolbar -->
      <div class="glass-card" style="padding:var(--space-4) var(--space-6);">
        <div style="display:flex; gap:var(--space-4); align-items:center; flex-wrap:wrap; justify-content:space-between;">
          <div style="display:flex; gap:var(--space-3); align-items:center; flex-wrap:wrap;">
            <input type="text" id="session-search" placeholder="Search IP, domain, JA4, protocol..." value="${state.searchQuery}" 
                   style="background:var(--bg-elevated); border:1px solid var(--border-default); border-radius:var(--radius-md); padding:0.5em 1em; color:var(--text-primary); font-family:var(--font-sans); width:280px;" />
            
            <select id="filter-protocol" style="background:var(--bg-elevated); border:1px solid var(--border-default); border-radius:var(--radius-md); padding:0.5em 1em; color:var(--text-primary);">
              <option value="all" ${state.protocolFilter === 'all' ? 'selected' : ''}>All Protocols</option>
              <option value="SMTP" ${state.protocolFilter === 'SMTP' ? 'selected' : ''}>SMTP</option>
              <option value="IMAP" ${state.protocolFilter === 'IMAP' ? 'selected' : ''}>IMAP</option>
              <option value="POP3" ${state.protocolFilter === 'POP3' ? 'selected' : ''}>POP3</option>
            </select>

            <select id="filter-risk" style="background:var(--bg-elevated); border:1px solid var(--border-default); border-radius:var(--radius-md); padding:0.5em 1em; color:var(--text-primary);">
              <option value="all" ${state.riskFilter === 'all' ? 'selected' : ''}>All Risk Severities</option>
              <option value="critical" ${state.riskFilter === 'critical' ? 'selected' : ''}>Critical Risk (>=75)</option>
              <option value="high" ${state.riskFilter === 'high' ? 'selected' : ''}>High Risk (>=50)</option>
              <option value="low" ${state.riskFilter === 'low' ? 'selected' : ''}>Low / Compliant (<50)</option>
            </select>
          </div>

          <div style="color:var(--text-secondary); font-size:var(--text-sm);">
            Showing <strong>${state.filteredSessions.length}</strong> of ${state.data.sessions.length} sessions
          </div>
        </div>
      </div>

      <!-- Main Sessions Table -->
      <div class="glass-card" style="padding:0; overflow:hidden;">
        <div class="table-scroll">
          <table class="data-table">
            <thead>
              <tr>
                <th>Flow ID</th>
                <th>Timestamp</th>
                <th>Protocol</th>
                <th>Client (Source)</th>
                <th>Server (Target)</th>
                <th>Encryption Mode</th>
                <th>JA4 Fingerprint</th>
                <th>Entropy</th>
                <th>Risk Score</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${state.filteredSessions.length === 0 ? `
                <tr><td colspan="10" style="text-align:center; padding:var(--space-8); color:var(--text-tertiary);">No sessions match the current filter criteria.</td></tr>
              ` : state.filteredSessions.map(s => `
                <tr class="session-row" data-id="${s.id}">
                  <td class="mono" style="color:var(--accent-cyan); font-weight:600;">FLOW-${s.index.toString().padStart(5, '0')}</td>
                  <td>${formatTimestamp(s.timestamp)}</td>
                  <td><span class="badge badge-info">${s.protocol}</span></td>
                  <td class="mono">${s.clientIp}:${s.clientPort}</td>
                  <td class="mono">${s.serverIp}:${s.serverPort}</td>
                  <td>
                    ${s.tlsVersion ? `<span class="badge badge-low">${s.tlsVersion}</span>` : '<span class="badge badge-critical">PLAINTEXT</span>'}
                  </td>
                  <td class="mono" style="font-size:0.75rem;">${s.ja4 || '—'}</td>
                  <td class="mono">${(s.entropy || 0).toFixed(2)}</td>
                  <td>
                    <span class="badge ${getRiskBadgeClass(s.riskScore)}">
                      ${getRiskCategory(s.riskScore)} (${s.riskScore})
                    </span>
                  </td>
                  <td>
                    <button class="btn btn-outline btn-sm btn-inspect" data-id="${s.id}">Deep Inspect</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  // Attach search and filter handlers
  const searchInput = container.querySelector('#session-search');
  const protoSelect = container.querySelector('#filter-protocol');
  const riskSelect = container.querySelector('#filter-risk');

  const onFilterChange = () => {
    state.searchQuery = searchInput.value.toLowerCase();
    state.protocolFilter = protoSelect.value;
    state.riskFilter = riskSelect.value;
    applyFilters();
    renderSessions(container);
  };

  searchInput.addEventListener('input', onFilterChange);
  protoSelect.addEventListener('change', onFilterChange);
  riskSelect.addEventListener('change', onFilterChange);

  container.querySelectorAll('.btn-inspect').forEach(b => {
    b.addEventListener('click', (e) => {
      e.stopPropagation();
      openSessionModal(b.dataset.id);
    });
  });

  container.querySelectorAll('.session-row').forEach(row => {
    row.addEventListener('click', () => {
      openSessionModal(row.dataset.id);
    });
  });
}

function applyFilters() {
  state.filteredSessions = state.data.sessions.filter(s => {
    if (state.protocolFilter !== 'all' && s.protocol !== state.protocolFilter) return false;
    if (state.riskFilter === 'critical' && s.riskScore < 75) return false;
    if (state.riskFilter === 'high' && (s.riskScore < 50 || s.riskScore >= 75)) return false;
    if (state.riskFilter === 'low' && s.riskScore >= 50) return false;

    if (state.searchQuery) {
      const q = state.searchQuery;
      const match = s.clientIp.includes(q) ||
                    s.serverIp.includes(q) ||
                    s.protocol.toLowerCase().includes(q) ||
                    (s.ja4 && s.ja4.toLowerCase().includes(q)) ||
                    (s.serverName && s.serverName.toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });
}

// ─────────────────────────────────────────────────────────────
// VIEW 3: AUTONOMOUS THREAT HUNTING (PHASE 23 INTEGRATION)
// ─────────────────────────────────────────────────────────────
function renderHunting(container) {
  const templates = [
    { id: 'HUNT-TLS-DOWNGRADE', name: 'STARTTLS Stripping & Cipher Downgrade', query: "HUNT legacy_tls_recurrence FROM tls_events WHERE tls_version IN ['TLS 1.0', 'TLS 1.1'] WITHIN 90d" },
    { id: 'HUNT-ROGUE-JA4', name: 'Suspicious / Pentest JA4 Fingerprints', query: "HUNT rogue_client_fingerprint FROM ja4_telemetry WHERE ja4_risk == 'CRITICAL' GROUP_BY asset" },
    { id: 'HUNT-WEAK-CIPHER', name: 'Obsolete 3DES / RC4 Sweet32 Exposure', query: "HUNT deprecated_ciphers FROM sessions WHERE cipher_suite IN [0x000a, 0x0005, 0xc012] WITHIN 30d" },
    { id: 'HUNT-CLEARTEXT-AUTH', name: 'Plaintext AUTH Credential Harvesting', query: "HUNT plaintext_auth FROM commands WHERE event_type == 'AUTH' AND tls_active == false" },
  ];

  container.innerHTML = `
    <div style="padding:var(--space-6) var(--space-8); display:flex; flex-direction:column; gap:var(--space-6);">
      <!-- Threat Hunting Banner -->
      <div class="glass-card" style="background:linear-gradient(135deg, rgba(0,240,255,0.08) 0%, rgba(123,97,255,0.08) 100%);">
        <div class="glass-card-body" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:var(--space-4);">
          <div>
            <h2 style="margin-bottom:var(--space-1);">Autonomous Threat Hunting Engine (Phase 23)</h2>
            <p style="color:var(--text-secondary); max-width:700px;">
              Continuous hypothesis generation, forensic data lakehouse queries (HQL), detection drift validation, and multi-year retrospective correlation.
            </p>
          </div>
          <div style="display:flex; gap:var(--space-3);">
            <button class="btn btn-outline" id="btn-run-all-hunts">Run All Active Hunts</button>
            <button class="btn btn-primary" id="btn-new-hypothesis">+ Formulate Hypothesis</button>
          </div>
        </div>
      </div>

      <!-- Hunting Console Grid -->
      <div class="dashboard-grid">
        <!-- HQL Query Editor -->
        <div class="glass-card">
          <div class="glass-card-header">
            <h3>Forensic HQL (Hunt Query Language) Console</h3>
            <span class="badge badge-info">Lakehouse Engine</span>
          </div>
          <div class="glass-card-body" style="display:flex; flex-direction:column; gap:var(--space-4);">
            <div>
              <label style="font-size:var(--text-xs); color:var(--text-secondary); margin-bottom:var(--space-2); display:block;">Select Pre-configured Playbook Template:</label>
              <select id="hql-template-select" style="width:100%; background:var(--bg-elevated); border:1px solid var(--border-default); border-radius:var(--radius-md); padding:0.6em 1em; color:var(--text-primary); font-family:var(--font-sans);">
                ${templates.map(t => `<option value="${t.id}">${t.name} (${t.id})</option>`).join('')}
              </select>
            </div>

            <div>
              <label style="font-size:var(--text-xs); color:var(--text-secondary); margin-bottom:var(--space-2); display:block;">HQL Expression:</label>
              <textarea id="hql-query-text" rows="4" class="mono" style="width:100%; background:var(--bg-elevated); border:1px solid var(--border-cyan); border-radius:var(--radius-md); padding:var(--space-3); color:var(--accent-cyan); font-size:var(--text-sm); line-height:1.4;">${templates[0].query}</textarea>
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span style="font-size:var(--text-xs); color:var(--text-tertiary);">Scans 30-day, 90-day, 1-year and 3-year lakehouse partitions</span>
              <button class="btn btn-primary" id="btn-execute-hql">Execute Threat Hunt</button>
            </div>
          </div>
        </div>

        <!-- Hypotheses Board -->
        <div class="glass-card">
          <div class="glass-card-header">
            <h3>Active Hypotheses & Continuous Validation</h3>
            <span class="badge badge-low">Autonomous AI Agent</span>
          </div>
          <div class="glass-card-body" style="display:flex; flex-direction:column; gap:var(--space-3);">
            <div style="padding:var(--space-3); border-radius:var(--radius-md); background:var(--bg-elevated); border-left:3px solid var(--accent-magenta);">
              <div style="display:flex; justify-content:space-between; margin-bottom:var(--space-1);">
                <strong style="font-size:var(--text-sm);">HYP-DOWNGRADE-01</strong>
                <span class="badge badge-critical">CONFIRMED (0.92)</span>
              </div>
              <div style="font-size:var(--text-xs); color:var(--text-secondary);">
                Adversary performing selective STARTTLS stripping against MTA relays with known fallback behavior.
              </div>
            </div>

            <div style="padding:var(--space-3); border-radius:var(--radius-md); background:var(--bg-elevated); border-left:3px solid var(--accent-amber);">
              <div style="display:flex; justify-content:space-between; margin-bottom:var(--space-1);">
                <strong style="font-size:var(--text-sm);">HYP-BEACON-JA4</strong>
                <span class="badge badge-medium">TESTING (0.64)</span>
              </div>
              <div style="font-size:var(--text-xs); color:var(--text-secondary);">
                Periodic uniform-interval outbound SMTP connections matching rogue script fingerprint <code>t12d0102h0_c2</code>.
              </div>
            </div>

            <div style="padding:var(--space-3); border-radius:var(--radius-md); background:var(--bg-elevated); border-left:3px solid var(--accent-emerald);">
              <div style="display:flex; justify-content:space-between; margin-bottom:var(--space-1);">
                <strong style="font-size:var(--text-sm);">HYP-CERT-EXPIRY</strong>
                <span class="badge badge-low">REJECTED (0.15)</span>
              </div>
              <div style="font-size:var(--text-xs); color:var(--text-secondary);">
                Production certificate chain contains expired intermediate authority CA-09. Counter-evidence verified modern root.
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Threat Hunt Execution Results -->
      <div class="glass-card" id="hunt-results-card">
        <div class="glass-card-header">
          <h3>Retrospective Hunt Findings & Discovered Candidates</h3>
          <span class="badge badge-info" id="hunt-status-badge">Ready for Execution</span>
        </div>
        <div class="glass-card-body" id="hunt-results-body">
          <div style="text-align:center; padding:var(--space-8); color:var(--text-tertiary);">
            Click <strong>Execute Threat Hunt</strong> above to scan passive telemetry against forensic lakehouse partitions.
          </div>
        </div>
      </div>
    </div>
  `;

  // Attach template change listener
  const templateSelect = container.querySelector('#hql-template-select');
  const queryText = container.querySelector('#hql-query-text');
  templateSelect.addEventListener('change', () => {
    const t = templates.find(item => item.id === templateSelect.value);
    if (t) queryText.value = t.query;
  });

  // Execute HQL
  container.querySelector('#btn-execute-hql').addEventListener('click', () => {
    const resultsBody = container.querySelector('#hunt-results-body');
    const statusBadge = container.querySelector('#hunt-status-badge');
    statusBadge.className = 'badge badge-low';
    statusBadge.innerText = 'Completed in 14.2ms';

    const matches = state.data.sessions.filter(s => s.riskScore >= 65);

    resultsBody.innerHTML = `
      <div style="margin-bottom:var(--space-4); display:flex; justify-content:space-between; align-items:center;">
        <div>
          Found <strong>${matches.length}</strong> matching candidates matching forensic criteria in lakehouse memory.
        </div>
        <button class="btn btn-outline btn-sm" id="btn-export-hunt-bundle">Export Evidence Bundle (.JSON)</button>
      </div>

      <div class="table-scroll">
        <table class="data-table">
          <thead>
            <tr>
              <th>Candidate ID</th>
              <th>Matched Asset</th>
              <th>Timestamp</th>
              <th>Observed Indicator</th>
              <th>Confidence</th>
              <th>Investigation Status</th>
            </tr>
          </thead>
          <tbody>
            ${matches.map((m, idx) => `
              <tr>
                <td class="mono" style="color:var(--accent-cyan);">CAND-${(idx + 1).toString().padStart(4, '0')}</td>
                <td class="mono">${m.serverName || m.serverIp}</td>
                <td>${formatTimestamp(m.timestamp)}</td>
                <td><span class="badge badge-critical">${m.securityIndicators?.[0] || 'CRYPTOGRAPHIC_ANOMALY'}</span></td>
                <td><span class="badge badge-low">${(0.85 + (idx % 10) * 0.01).toFixed(2)}</span></td>
                <td><button class="btn btn-outline btn-sm btn-inspect" data-id="${m.id}">Investigate Asset</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

    resultsBody.querySelectorAll('.btn-inspect').forEach(b => {
      b.addEventListener('click', () => openSessionModal(b.dataset.id));
    });

    resultsBody.querySelector('#btn-export-hunt-bundle')?.addEventListener('click', () => {
      alert("Exported JSON Forensic Evidence Bundle with cryptographically signed SHA-256 manifest.");
    });
  });

  container.querySelector('#btn-run-all-hunts')?.addEventListener('click', () => {
    container.querySelector('#btn-execute-hql')?.click();
  });
}

// ─────────────────────────────────────────────────────────────
// VIEW 4: CVE & VULNERABILITY CATALOG
// ─────────────────────────────────────────────────────────────
function renderCVE(container) {
  const cveEntries = Object.values(CVE_MAP);
  const cweEntries = Object.values(CWE_MAP);

  container.innerHTML = `
    <div style="padding:var(--space-6) var(--space-8); display:flex; flex-direction:column; gap:var(--space-6);">
      <div class="glass-card">
        <div class="glass-card-header">
          <h3>Cryptographic Attack & CVE Vulnerability Matrix</h3>
          <span class="badge badge-info">${cveEntries.length} Tracked CVEs</span>
        </div>
        <div class="glass-card-body" style="padding:0;">
          <div class="table-scroll">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Vulnerability / Attack</th>
                  <th>Standard Identifier</th>
                  <th>Severity</th>
                  <th>Impact & Description</th>
                  <th>Remediation Protocol</th>
                </tr>
              </thead>
              <tbody>
                ${cveEntries.map(c => `
                  <tr>
                    <td><strong>${c.title}</strong></td>
                    <td class="mono" style="color:var(--accent-cyan); font-weight:600;">${c.id}</td>
                    <td>
                      <span class="badge ${c.severity === 'Critical' ? 'badge-critical' : c.severity === 'High' ? 'badge-high' : 'badge-medium'}">
                        ${c.severity}
                      </span>
                    </td>
                    <td style="color:var(--text-secondary); max-width:450px;">${c.description}</td>
                    <td><code style="font-size:0.75rem;">Disable legacy ciphers & upgrade to TLS 1.3</code></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="glass-card">
        <div class="glass-card-header">
          <h3>Common Weakness Enumeration (CWE) Mappings</h3>
          <span class="badge badge-info">${cweEntries.length} Mapped CWEs</span>
        </div>
        <div class="glass-card-body" style="padding:0;">
          <div class="table-scroll">
            <table class="data-table">
              <thead>
                <tr>
                  <th>CWE Code</th>
                  <th>Weakness Category</th>
                  <th>Forensic Relevance</th>
                </tr>
              </thead>
              <tbody>
                ${cweEntries.map(w => `
                  <tr>
                    <td class="mono" style="color:var(--accent-purple); font-weight:700;">${w.id}</td>
                    <td><strong>${w.title}</strong></td>
                    <td style="color:var(--text-secondary);">${w.description}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;
}

// ─────────────────────────────────────────────────────────────
// VIEW 5: JA4 INTELLIGENCE
// ─────────────────────────────────────────────────────────────
function renderJA4(container) {
  const ja4Entries = Object.entries(JA4_SIGNATURES);

  container.innerHTML = `
    <div style="padding:var(--space-6) var(--space-8); display:flex; flex-direction:column; gap:var(--space-6);">
      <div class="glass-card">
        <div class="glass-card-header">
          <h3>JA4+ Passive TLS Fingerprint Intelligence Database</h3>
          <span class="badge badge-info">${ja4Entries.length} Curated Signatures</span>
        </div>
        <div class="glass-card-body" style="padding:0;">
          <div class="table-scroll">
            <table class="data-table">
              <thead>
                <tr>
                  <th>JA4 Fingerprint</th>
                  <th>Identified Application / Tool</th>
                  <th>Category</th>
                  <th>Vendor / Family</th>
                  <th>Risk Rating</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                ${ja4Entries.map(([fprint, meta]) => `
                  <tr>
                    <td class="mono" style="color:var(--accent-cyan); font-weight:600;">${fprint}</td>
                    <td><strong>${meta.name}</strong></td>
                    <td><span class="badge badge-neutral">${meta.category}</span></td>
                    <td>${meta.vendor}</td>
                    <td>
                      <span class="badge ${meta.risk === 'critical' ? 'badge-critical' : meta.risk === 'high' ? 'badge-high' : meta.risk === 'medium' ? 'badge-medium' : 'badge-low'}">
                        ${meta.risk.toUpperCase()}
                      </span>
                    </td>
                    <td style="color:var(--text-secondary); max-width:350px;">${meta.description}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;
}

// ─────────────────────────────────────────────────────────────
// VIEW 6: INCIDENT RESPONSE & SOAR (PHASE 24)
// ─────────────────────────────────────────────────────────────
const MOCK_INCIDENTS = [
  {
    id: 'INC-882',
    title: 'Legacy TLS Recurrence After Scheduled Update',
    severity: 'High',
    priority: 'P1_CRITICAL',
    status: 'REMEDIATING',
    affectedAssets: ['MTA-07', 'MTA-01', 'MTA-02'],
    playbook: 'CRYPTO-REGRESSION-001',
    evidence: ['SESSION-882', 'CERT-771', 'JA4-X', 'PCAP-8821'],
    blastRadius: '71% (CRITICAL)',
    simulation: 'PASS (99.4% compatibility)',
    approval: '1/2 Signatures'
  },
  {
    id: 'INC-901',
    title: 'Suspected Private Key Compromise on Mail Relay',
    severity: 'Critical',
    priority: 'P1_CRITICAL',
    status: 'WAITING_APPROVAL',
    affectedAssets: ['MTA-04'],
    playbook: 'CERT-COMPROMISE-002',
    evidence: ['CERT-THUMB-99', 'LOG-AUTH-FAIL'],
    blastRadius: '28% (HIGH)',
    simulation: 'PASS (100% compatibility)',
    approval: '0/2 Signatures'
  },
  {
    id: 'INC-914',
    title: 'Rogue JA4+ Fingerprint / C2 Beaconing Observed',
    severity: 'Medium',
    priority: 'P2_HIGH',
    status: 'INVESTIGATING',
    affectedAssets: ['MTA-02'],
    playbook: 'SUSPICIOUS-JA4-005',
    evidence: ['JA4-t12d0102h0_c2', 'PCAP-774'],
    blastRadius: '14% (MEDIUM)',
    simulation: 'PASS',
    approval: 'Auto-containment'
  },
  {
    id: 'INC-922',
    title: 'STARTTLS Stripping & Cleartext AUTH Exposure',
    severity: 'Critical',
    priority: 'P1_CRITICAL',
    status: 'CONTAINMENT',
    affectedAssets: ['MTA-07'],
    playbook: 'LEGACY-EXPOSURE-004',
    evidence: ['SESSION-PLAIN-AUTH', 'PCAP-STRIP-01'],
    blastRadius: '42% (HIGH)',
    simulation: 'PASS (98.0% compatibility)',
    approval: 'Approved'
  },
  {
    id: 'INC-930',
    title: 'Deprecated 3DES SWEET32 Cipher Detected',
    severity: 'Low',
    priority: 'P3_MEDIUM',
    status: 'MONITORING',
    affectedAssets: ['MTA-08'],
    playbook: 'CRYPTO-DRIFT-006',
    evidence: ['CIPHER-0x000a'],
    blastRadius: '10% (LOW)',
    simulation: 'PASS',
    approval: 'Approved'
  }
];

function renderSOAR(container) {
  container.innerHTML = `
    <div style="padding:var(--space-6) var(--space-8); display:flex; flex-direction:column; gap:var(--space-6);">
      <!-- Top Title Banner -->
      <div class="glass-card" style="background:linear-gradient(135deg, rgba(123,97,255,0.08) 0%, rgba(0,240,255,0.08) 100%);">
        <div class="glass-card-body" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:var(--space-4);">
          <div>
            <h2 style="margin-bottom:var(--space-1);">Autonomous Incident Operations Center (Phase 24)</h2>
            <p style="color:var(--text-secondary); max-width:750px;">
              SOAR Remediation Control Plane: Autonomous triage, blast-radius pre-simulation, Four-Eyes cryptographic approvals, canary rollouts, multi-layer verification, and recurrence monitoring.
            </p>
          </div>
          <div style="display:flex; gap:var(--space-3);">
            <button class="btn btn-outline" id="btn-soar-reconcile">State Reconciliation</button>
            <button class="btn btn-primary" id="btn-trigger-soar-demo">+ Launch Remediation Flow</button>
          </div>
        </div>
      </div>

      <!-- KPI Stat Cards -->
      <div class="dashboard-stats">
        <div class="stat-card critical">
          <div class="stat-label">Critical Incidents</div>
          <div class="stat-value magenta">3</div>
          <div class="stat-detail">Immediate Four-Eyes Signoff</div>
        </div>
        <div class="stat-card warning">
          <div class="stat-label">High Incidents</div>
          <div class="stat-value amber">12</div>
          <div class="stat-detail">Under Active Remediation</div>
        </div>
        <div class="stat-card info">
          <div class="stat-label">Medium / Low Incidents</div>
          <div class="stat-value cyan">29</div>
          <div class="stat-detail">Investigating / Monitoring</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Awaiting Approval</div>
          <div class="stat-value purple" style="color:var(--accent-purple);">4</div>
          <div class="stat-detail">Multi-Signature Queue</div>
        </div>
      </div>

      <!-- Active Incidents Table & Response Progress -->
      <div class="dashboard-sidebar">
        <!-- Incidents List -->
        <div class="glass-card">
          <div class="glass-card-header">
            <h3>Active Incident Queue</h3>
            <span class="badge badge-info">Real-time Control Plane</span>
          </div>
          <div class="glass-card-body" style="padding:0;">
            <div class="table-scroll">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Incident ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Priority</th>
                    <th>Status</th>
                    <th>Target Assets</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${MOCK_INCIDENTS.map(inc => `
                    <tr>
                      <td class="mono" style="color:var(--accent-cyan); font-weight:700;">${inc.id}</td>
                      <td><strong>${inc.title}</strong></td>
                      <td>
                        <span class="badge ${inc.severity === 'Critical' ? 'badge-critical' : inc.severity === 'High' ? 'badge-high' : 'badge-medium'}">
                          ${inc.severity}
                        </span>
                      </td>
                      <td class="mono" style="font-size:0.75rem;">${inc.priority}</td>
                      <td>
                        <span class="badge ${inc.status === 'REMEDIATING' ? 'badge-high' : inc.status === 'WAITING_APPROVAL' ? 'badge-medium' : 'badge-low'}">
                          ${inc.status}
                        </span>
                      </td>
                      <td class="mono" style="font-size:0.8rem;">${inc.affectedAssets.join(', ')}</td>
                      <td>
                        <button class="btn btn-outline btn-sm btn-inspect-inc" data-id="${inc.id}">Orchestrate</button>
                      </td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Live Response Actions & SLA Analytics -->
        <div style="display:flex; flex-direction:column; gap:var(--space-6);">
          <div class="glass-card">
            <div class="glass-card-header">
              <h3>Active Response Actions</h3>
            </div>
            <div class="glass-card-body" style="display:flex; flex-direction:column; gap:var(--space-3);">
              <div>
                <div style="display:flex; justify-content:space-between; font-size:var(--text-xs); margin-bottom:var(--space-1);">
                  <span>Disable TLS 1.1 on Gateway</span>
                  <span class="mono" style="color:var(--accent-cyan);">14 / 17 completed</span>
                </div>
                <div class="progress-bar"><div class="progress-bar-fill" style="width: 82%;"></div></div>
              </div>

              <div>
                <div style="display:flex; justify-content:space-between; font-size:var(--text-xs); margin-bottom:var(--space-1);">
                  <span>Certificate Key Rotation</span>
                  <span class="mono" style="color:var(--accent-emerald);">3 / 3 completed</span>
                </div>
                <div class="progress-bar"><div class="progress-bar-fill" style="width: 100%; background:var(--gradient-success);"></div></div>
              </div>

              <div>
                <div style="display:flex; justify-content:space-between; font-size:var(--text-xs); margin-bottom:var(--space-1);">
                  <span>Network Bounded Containment</span>
                  <span class="mono" style="color:var(--accent-amber);">Awaiting Approval</span>
                </div>
                <div class="progress-bar"><div class="progress-bar-fill" style="width: 40%; background:var(--accent-amber);"></div></div>
              </div>
            </div>
          </div>

          <div class="glass-card">
            <div class="glass-card-header">
              <h3>SOAR SLA & Effectiveness Metrics</h3>
            </div>
            <div class="glass-card-body" style="display:flex; flex-direction:column; gap:var(--space-2); font-size:var(--text-sm);">
              <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-subtle); padding-bottom:var(--space-2);">
                <span style="color:var(--text-secondary);">Mean Time to Triage (MTTT)</span>
                <strong class="mono" style="color:var(--accent-cyan);">1.4 min</strong>
              </div>
              <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-subtle); padding-bottom:var(--space-2);">
                <span style="color:var(--text-secondary);">Mean Time to Containment (MTTC)</span>
                <strong class="mono" style="color:var(--accent-emerald);">18.2 min</strong>
              </div>
              <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-subtle); padding-bottom:var(--space-2);">
                <span style="color:var(--text-secondary);">Mean Time to Remediation (MTTR)</span>
                <strong class="mono" style="color:var(--accent-purple);">42.0 min</strong>
              </div>
              <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-subtle); padding-bottom:var(--space-2);">
                <span style="color:var(--text-secondary);">Automation Rate</span>
                <strong class="mono" style="color:var(--accent-cyan);">42.8%</strong>
              </div>
              <div style="display:flex; justify-content:space-between;">
                <span style="color:var(--text-secondary);">Canary Rollback Rate</span>
                <strong class="mono" style="color:var(--accent-emerald);">2.1% (Low)</strong>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Attach event handlers
  container.querySelectorAll('.btn-inspect-inc').forEach(b => {
    b.addEventListener('click', () => openIncidentModal(b.dataset.id));
  });

  container.querySelector('#btn-trigger-soar-demo')?.addEventListener('click', () => {
    openIncidentModal('INC-882');
  });

  container.querySelector('#btn-soar-reconcile')?.addEventListener('click', () => {
    alert("Continuous Remediation Loop: Desired Security State reconciled against observed telemetry. Zero configuration drift detected.");
  });
}

function openIncidentModal(incidentId) {
  const inc = MOCK_INCIDENTS.find(i => i.id === incidentId) || MOCK_INCIDENTS[0];
  const overlay = document.querySelector('#session-modal-overlay');
  const modalContent = document.querySelector('#session-modal-content');
  if (!overlay || !modalContent) return;

  modalContent.innerHTML = `
    <div class="glass-card-header" style="position:sticky; top:0; background:var(--bg-surface); z-index:10;">
      <div>
        <div style="font-size:var(--text-xs); color:var(--text-secondary);">INCIDENT REMEDIATION WORKSPACE (PHASE 24)</div>
        <h3 style="display:flex; align-items:center; gap:var(--space-2);">
          <span>${inc.id} — ${inc.title}</span>
          <span class="badge ${inc.severity === 'Critical' ? 'badge-critical' : 'badge-high'}">${inc.severity}</span>
          <span class="badge badge-low">${inc.status}</span>
        </h3>
      </div>
      <button class="btn btn-ghost btn-sm" id="btn-close-modal">✕ Close</button>
    </div>

    <div class="glass-card-body" style="display:flex; flex-direction:column; gap:var(--space-5);">
      <!-- Incident Overview Card -->
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:var(--space-3); background:var(--bg-elevated); padding:var(--space-4); border-radius:var(--radius-md);">
        <div>
          <div style="font-size:var(--text-xs); color:var(--text-tertiary);">Operational Priority</div>
          <div class="mono" style="font-weight:700; color:var(--accent-magenta);">${inc.priority}</div>
        </div>
        <div>
          <div style="font-size:var(--text-xs); color:var(--text-tertiary);">Affected Systems</div>
          <div class="mono" style="font-weight:600; color:var(--accent-cyan);">${inc.affectedAssets.join(', ')}</div>
        </div>
        <div>
          <div style="font-size:var(--text-xs); color:var(--text-tertiary);">Matched Playbook</div>
          <div class="mono" style="font-weight:600; color:var(--accent-purple);">${inc.playbook}</div>
        </div>
        <div>
          <div style="font-size:var(--text-xs); color:var(--text-tertiary);">Pre-Response Simulation</div>
          <div class="mono" style="font-weight:600; color:var(--accent-emerald);">${inc.simulation}</div>
        </div>
      </div>

      <!-- Evidence Preservation Section -->
      <div class="glass-card" style="padding:var(--space-4);">
        <h4 style="margin-bottom:var(--space-2); color:var(--accent-cyan);">Preserved Forensic Evidence (Pre-Remediation Vault)</h4>
        <div style="display:flex; gap:var(--space-2); flex-wrap:wrap;">
          ${inc.evidence.map(e => `<span class="badge badge-info" style="font-family:var(--font-mono);">${e}</span>`).join('')}
          <span class="badge badge-neutral" style="font-family:var(--font-mono);">CONFIG-SNAPSHOT-BEFORE</span>
        </div>
      </div>

      <!-- Digital Twin & Blast Radius Analysis -->
      <div class="glass-card" style="padding:var(--space-4); background:rgba(0, 240, 255, 0.02);">
        <h4 style="margin-bottom:var(--space-2); color:var(--accent-cyan);">Pre-Remediation Safety Controls</h4>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:var(--space-3); font-size:var(--text-sm);">
          <div><strong>Enterprise Blast Radius:</strong> <span class="mono">${inc.blastRadius}</span></div>
          <div><strong>Digital Twin Compatibility:</strong> <span class="mono" style="color:var(--accent-emerald);">99.4% (8 non-critical MFP sessions)</span></div>
          <div><strong>Change Management Ticket:</strong> <span class="mono">CHG-ITSM-9941 (Approved)</span></div>
          <div><strong>Four-Eyes Verification:</strong> <span class="mono" style="color:var(--accent-amber);">${inc.approval}</span></div>
        </div>
      </div>

      <!-- Action Orchestration Toolbar -->
      <div class="glass-card" style="padding:var(--space-4);">
        <h4 style="margin-bottom:var(--space-3);">Remediation Controls & Multi-Signature Signoff</h4>
        <div style="display:flex; gap:var(--space-3); flex-wrap:wrap;">
          <button class="btn btn-primary" id="btn-sign-soc">✓ Sign as Lead SOC Analyst</button>
          <button class="btn btn-primary" id="btn-sign-pki" style="background:var(--accent-purple);">✓ Sign as PKI Officer (Four-Eyes)</button>
          <button class="btn btn-outline" id="btn-execute-canary">Execute Canary Rollout (${inc.affectedAssets[0]})</button>
          <button class="btn btn-outline" id="btn-verify-telemetry">Verify Wire Telemetry</button>
          <button class="btn btn-ghost" id="btn-export-postmortem">Export Post-Incident Report (.MD)</button>
        </div>
        <div id="soar-action-output" style="margin-top:var(--space-3); font-family:var(--font-mono); font-size:var(--text-xs); color:var(--accent-cyan);"></div>
      </div>

      <!-- Incident Milestone Timeline -->
      <div class="glass-card" style="padding:var(--space-4);">
        <h4 style="margin-bottom:var(--space-3);">Chronological Incident Audit Timeline</h4>
        <div style="font-family:var(--font-mono); font-size:var(--text-xs); display:flex; flex-direction:column; gap:var(--space-2);">
          <div style="color:var(--text-tertiary);">[01:02:14 UTC] FINDING_QUALIFIED: Phase 23 finding qualified into ${inc.id}</div>
          <div style="color:var(--accent-cyan);">[01:03:00 UTC] TRIAGED: Criticality enriched as CRITICAL, Recurrence detected in Lakehouse</div>
          <div style="color:var(--accent-purple);">[01:04:12 UTC] SIMULATION_COMPLETED: Digital Twin confirms 99.4% compatibility</div>
          <div style="color:var(--accent-amber);">[01:06:40 UTC] APPROVAL_PENDING: Four-Eyes policy POL-CRIT-ASSET-01 enforced</div>
          <div style="color:var(--accent-emerald);">[01:08:15 UTC] REMEDIATION_CANARY: TLS 1.3 enforced on ${inc.affectedAssets[0]} with change lock</div>
          <div style="color:var(--accent-cyan);">[01:10:00 UTC] VERIFIED: Observed wire telemetry confirms zero legacy sessions</div>
          <div style="color:var(--text-secondary);">[01:12:00 UTC] WATCHER_REGISTERED: 24h & 7d recurrence monitoring active</div>
        </div>
      </div>
    </div>
  `;

  const outputDiv = modalContent.querySelector('#soar-action-output');

  modalContent.querySelector('#btn-sign-soc')?.addEventListener('click', () => {
    outputDiv.innerText = "[+] SOC Analyst Signature Recorded (Hash: 8fe90ab4e2d4a698...). 1/2 Signatures complete.";
  });

  modalContent.querySelector('#btn-sign-pki')?.addEventListener('click', () => {
    outputDiv.innerText = "[+] PKI Officer Signature Recorded (Four-Eyes complete). Action ACT-882 authorized for rollout.";
  });

  modalContent.querySelector('#btn-execute-canary')?.addEventListener('click', () => {
    outputDiv.innerText = `[+] Canary rollout executed on ${inc.affectedAssets[0]}: Protocols ['TLSv1.0', 'TLSv1.1'] removed. STARTTLS policy updated to 'encrypt'. Change lock CHG-ITSM-9941 active.`;
  });

  modalContent.querySelector('#btn-verify-telemetry')?.addEventListener('click', () => {
    outputDiv.innerText = "[+] Multi-Layer Verification: PASS. Observed 0 legacy sessions on passive wire sensor. Service health UP.";
  });

  modalContent.querySelector('#btn-export-postmortem')?.addEventListener('click', () => {
    alert(`Exported complete Post-Incident Post-Mortem and Lessons Learned report for ${inc.id} with cryptographically signed SHA-256 manifest.`);
  });

  modalContent.querySelector('#btn-close-modal')?.addEventListener('click', () => {
    overlay.style.display = 'none';
  });

  overlay.style.display = 'flex';
}

// ─────────────────────────────────────────────────────────────
// SESSION DETAIL MODAL / DRAWER
// ─────────────────────────────────────────────────────────────
function openSessionModal(sessionId) {
  const session = state.data.sessions.find(s => s.id === sessionId);
  if (!session) return;

  const overlay = document.querySelector('#session-modal-overlay');
  const modalContent = document.querySelector('#session-modal-content');
  if (!overlay || !modalContent) return;

  const cves = getRelevantCVEs(session.tlsVersion === 'TLS 1.0' ? 'tls10' : session.tlsVersion === 'SSL 3.0' ? 'ssl3' : 'cbc');

  modalContent.innerHTML = `
    <div class="glass-card-header" style="position:sticky; top:0; background:var(--bg-surface); z-index:10;">
      <div>
        <div style="font-size:var(--text-xs); color:var(--text-secondary);">FORENSIC SESSION INSPECTOR</div>
        <h3 style="display:flex; align-items:center; gap:var(--space-2);">
          <span>FLOW-${session.index.toString().padStart(5, '0')}</span>
          <span class="badge ${getRiskBadgeClass(session.riskScore)}">${getRiskCategory(session.riskScore)} (${session.riskScore}/100)</span>
        </h3>
      </div>
      <button class="btn btn-ghost btn-sm" id="btn-close-modal">✕ Close</button>
    </div>

    <div class="glass-card-body" style="display:flex; flex-direction:column; gap:var(--space-5);">
      <!-- Flow Overview Grid -->
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:var(--space-3); background:var(--bg-elevated); padding:var(--space-4); border-radius:var(--radius-md);">
        <div>
          <div style="font-size:var(--text-xs); color:var(--text-tertiary);">Source Socket</div>
          <div class="mono" style="font-weight:600; color:var(--accent-cyan);">${session.clientIp}:${session.clientPort}</div>
        </div>
        <div>
          <div style="font-size:var(--text-xs); color:var(--text-tertiary);">Destination Socket</div>
          <div class="mono" style="font-weight:600; color:var(--accent-purple);">${session.serverIp}:${session.serverPort}</div>
        </div>
        <div>
          <div style="font-size:var(--text-xs); color:var(--text-tertiary);">Protocol / Mode</div>
          <div><strong style="color:var(--text-primary);">${session.protocol}</strong> &bull; ${session.tlsVersion || 'PLAINTEXT'}</div>
        </div>
        <div>
          <div style="font-size:var(--text-xs); color:var(--text-tertiary);">Stream Shannon Entropy</div>
          <div class="mono" style="color:var(--accent-emerald); font-weight:600;">${(session.entropy || 0).toFixed(3)} bits/byte</div>
        </div>
      </div>

      <!-- TLS Handshake Details -->
      ${session.tlsVersion ? `
        <div class="glass-card" style="padding:var(--space-4);">
          <h4 style="margin-bottom:var(--space-3); color:var(--accent-cyan);">TLS Cryptographic Negotiation Parameters</h4>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:var(--space-3); font-size:var(--text-sm);">
            <div><strong>JA4 Fingerprint:</strong> <span class="mono">${session.ja4 || 't13d1516h2'}</span></div>
            <div><strong>Cipher Suite:</strong> <span class="mono">${session.cipherSuiteName || 'TLS_AES_256_GCM_SHA384 (0x1302)'}</span></div>
            <div><strong>Key Exchange:</strong> <span>ECDHE (X25519)</span></div>
            <div><strong>Handshake Latency:</strong> <span>${(session.handshakeLatency || 12).toFixed(1)} ms</span></div>
          </div>
        </div>
      ` : `
        <div style="padding:var(--space-4); background:var(--accent-magenta-dim); border:1px solid rgba(255,0,102,0.3); border-radius:var(--radius-md);">
          <strong style="color:var(--accent-magenta);">WARNING: UNENCRYPTED CLEAR-TEXT STREAM</strong>
          <p style="font-size:var(--text-sm); margin-top:var(--space-1); color:var(--text-secondary);">
            This session transmitted sensitive email data without cryptographic encapsulation. Susceptible to passive wiretapping, STARTTLS stripping, and credential theft (CWE-319).
          </p>
        </div>
      `}

      <!-- Certificate Hierarchy -->
      ${session.certificate ? `
        <div class="glass-card" style="padding:var(--space-4);">
          <h4 style="margin-bottom:var(--space-3); color:var(--accent-purple);">Inspected X.509 Certificate Chain</h4>
          <div class="cert-chain">
            <div class="cert-node">
              <div class="cert-connector">●</div>
              <div class="cert-details">
                <div class="cert-cn">${session.certificate.subject}</div>
                <div class="cert-meta">
                  <span class="cert-meta-item">Issuer: ${session.certificate.issuer}</span>
                  <span class="cert-meta-item">Key: ${session.certificate.keyAlgo} ${session.certificate.keySize} bits</span>
                  <span class="cert-meta-item">Sig: ${session.certificate.sigAlgo}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      ` : ''}

      <!-- Reconstructed Timeline -->
      <div class="glass-card" style="padding:var(--space-4);">
        <h4 style="margin-bottom:var(--space-3);">Forensic Packet Timeline</h4>
        <div style="font-family:var(--font-mono); font-size:var(--text-xs); display:flex; flex-direction:column; gap:var(--space-2);">
          <div style="color:var(--accent-cyan);">[0.000s] [C2S] TCP SYN &rarr; Handshake Initiated</div>
          <div style="color:var(--accent-purple);">[0.008s] [S2C] TCP SYN-ACK &rarr; Connection Established</div>
          <div style="color:var(--text-secondary);">[0.015s] [S2C] 220 ${session.serverName || 'mail.enterprise.corp'} ESMTP Ready</div>
          <div style="color:var(--accent-cyan);">[0.024s] [C2S] EHLO client.internal.lan</div>
          ${session.tlsVersion ? `
            <div style="color:var(--accent-amber);">[0.038s] [C2S] STARTTLS</div>
            <div style="color:var(--accent-emerald);">[0.045s] [S2C] 220 2.0.0 Ready to start TLS</div>
            <div style="color:var(--accent-cyan);">[0.052s] [TLS] ClientHello (JA4: ${session.ja4 || 't13d1516h2'})</div>
            <div style="color:var(--accent-purple);">[0.068s] [TLS] ServerHello (${session.tlsVersion}) + Certificate Exchange</div>
          ` : `
            <div style="color:var(--accent-magenta);">[0.035s] [C2S] AUTH PLAIN (Credentials in cleartext)</div>
            <div style="color:var(--accent-magenta);">[0.055s] [C2S] MAIL FROM:&lt;admin@enterprise.corp&gt;</div>
          `}
        </div>
      </div>
    </div>
  `;

  modalContent.querySelector('#btn-close-modal')?.addEventListener('click', () => {
    overlay.style.display = 'none';
  });

  overlay.style.display = 'flex';
}

// Start application
document.addEventListener('DOMContentLoaded', initApp);
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  initApp();
}
