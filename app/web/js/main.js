/**
 * OTORI Dashboard - Main Application
 * Initialization, navigation, dashboard updates, and WebSocket handling
 */

// Cache for KPI data
let cachedKpi = null;

// ═══════════════════════════════════════════════════════════════
// Navigation
// ═══════════════════════════════════════════════════════════════

function initNavigation() {
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('page-' + btn.dataset.page).classList.add('active');
    });
  });
}

// ═══════════════════════════════════════════════════════════════
// Render Functions
// ═══════════════════════════════════════════════════════════════

function renderTopList(containerId, items, key) {
  const container = document.getElementById(containerId);
  if (!items || items.length === 0) {
    container.innerHTML = `<div class="empty-state">${t('empty.noData')}</div>`;
    return;
  }
  const isIpList = containerId === 'top-ips';
  const isPasswordList = containerId === 'top-passwords';

  container.innerHTML = items.slice(0, 10).map((item, i) => {
    let onclick = '';
    if (isIpList) {
      onclick = `onclick="openIpModal('${esc(item[key])}')"`;
    } else if (isPasswordList) {
      onclick = `onclick="showPasswordDetails('${esc(item[key]).replace(/'/g, "\\'")}')"`;
    }

    return `
      <div class="top-item ${isIpList || isPasswordList ? 'clickable' : ''}" ${onclick}>
        <span class="rank ${i < 3 ? 'top3' : ''}">${i + 1}</span>
        <div class="content">
          <div class="name">${esc(item[key])}</div>
        </div>
        <span class="count">${item.count}</span>
      </div>
    `;
  }).join('');
}

function renderDangerousCmds(items) {
  const container = document.getElementById('top-dangerous');
  if (!items || items.length === 0) {
    container.innerHTML = `<div class="empty-state">${t('empty.noData')}</div>`;
    return;
  }
  container.innerHTML = items.slice(0, 8).map((item, i) => `
    <div class="top-item clickable" onclick="showCommandDetails('${esc(item.command || '').replace(/'/g, "\\'")}')">
      <span class="severity-badge ${item.severity}">${item.severity}</span>
      <div class="content">
        <div class="name">${esc(item.command?.substring(0, 40) || '')}</div>
        <div class="meta">${item.category || ''}</div>
      </div>
      <span class="count">${item.count}</span>
    </div>
  `).join('');
}

function renderMitreTechniques(techniques) {
  const container = document.getElementById('top-mitre');
  if (!techniques || techniques.length === 0) {
    container.innerHTML = `<div class="empty-state">${t('empty.noData')}</div>`;
    return;
  }
  container.innerHTML = techniques.slice(0, 8).map(tech => `
    <div class="mitre-item clickable" style="cursor: pointer;" onclick="showMitreDetails('${tech.technique || tech.technique_id || ''}', '${esc(tech.name || '')}')">
      <span class="id">${tech.technique || tech.technique_id || ''}</span>
      <span class="name">${tech.name || ''}</span>
      <span class="count">${tech.count}</span>
    </div>
  `).join('');
}

// ═══════════════════════════════════════════════════════════════
// Dashboard Update
// ═══════════════════════════════════════════════════════════════

function updateDashboard(kpi, recent) {
  // Cache KPI data for modals
  cachedKpi = kpi;

  // Overview KPIs
  document.getElementById('kpi-sessions').textContent = kpi.total_sessions || 0;
  document.getElementById('kpi-ips').textContent = kpi.unique_ips || 0;
  document.getElementById('kpi-commands').textContent = kpi.total_commands || 0;
  document.getElementById('kpi-cmds-session').textContent = kpi.cmds_per_session || 0;
  document.getElementById('kpi-duration').textContent = fmtDuration(kpi.avg_duration_sec);
  document.getElementById('timeline-total').textContent = `${kpi.total_sessions || 0} sessions`;

  // Auth stats
  document.getElementById('login-success').textContent = kpi.login_success || 0;
  document.getElementById('login-failed').textContent = kpi.login_failed || 0;
  document.getElementById('unique-usernames').textContent = kpi.unique_usernames || 0;
  document.getElementById('unique-passwords').textContent = kpi.unique_passwords || 0;

  // Analytics KPIs
  document.getElementById('kpi-critical').textContent = kpi.critical_commands || 0;
  document.getElementById('kpi-high-sessions').textContent = (kpi.sessions_critical || 0) + (kpi.sessions_high || 0);
  document.getElementById('kpi-mitre').textContent = kpi.top_mitre_techniques?.length || 0;
  document.getElementById('kpi-bot-ratio').textContent = Math.round(kpi.bot_ratio || 0) + '%';

  // Activity chart
  if (activityChart && kpi.sessions_timeline) {
    activityChart.data.labels = kpi.sessions_timeline.map(t => t.label);
    activityChart.data.datasets[0].data = kpi.sessions_timeline.map(t => t.count);
    activityChart.data.datasets[1].data = kpi.commands_timeline?.map(t => t.count) || [];
    activityChart.update('none');
  }

  // Login chart
  if (loginChart) {
    loginChart.data.datasets[0].data = [kpi.login_success || 0, kpi.login_failed || 0];
    loginChart.update('none');
  }

  // Category chart
  if (categoryChart && kpi.category_distribution) {
    const cats = kpi.category_distribution.slice(0, 8);
    categoryChart.data.labels = cats.map(c => c.category);
    categoryChart.data.datasets[0].data = cats.map(c => c.count);
    categoryChart.data.datasets[0].backgroundColor = cats.map(c => CATEGORY_COLORS[c.category] || COLORS.muted);
    categoryChart.update('none');
  }

  // Severity chart
  if (severityChart && kpi.severity_distribution) {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const sevs = order.map(s => kpi.severity_distribution.find(x => x.severity === s)).filter(Boolean);
    severityChart.data.labels = sevs.map(s => s.severity);
    severityChart.data.datasets[0].data = sevs.map(s => s.count);
    severityChart.data.datasets[0].backgroundColor = sevs.map(s => SEVERITY_COLORS[s.severity] || COLORS.muted);
    severityChart.update('none');
  }

  // Top lists
  renderTopList('top-ips', kpi.top_ips, 'ip');
  renderTopList('top-passwords', kpi.top_passwords, 'password');
  renderDangerousCmds(kpi.top_dangerous_commands);
  renderMitreTechniques(kpi.top_mitre_techniques);

  // Geography page
  if (typeof updateGeographyPage === 'function') {
    updateGeographyPage(kpi);
  }

  // Sessions table - store all sessions and apply filters
  allSessions = recent || [];
  updateCountryDropdown();
  applyFilters();
  renderFilteredSessions();
  updateFilterSummary();
}

// ═══════════════════════════════════════════════════════════════
// WebSocket
// ═══════════════════════════════════════════════════════════════

function initWebSocket() {
  const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${wsProtocol}//${location.host}/ws`);
  ws.onopen = () => ws.send('subscribe');
  ws.onmessage = (msg) => {
    try {
      const data = JSON.parse(msg.data);
      if (data.type === 'update') updateDashboard(data.kpi, data.recent);
    } catch (e) {}
  };
  ws.onclose = () => setTimeout(() => location.reload(), 5000);
}

// ═══════════════════════════════════════════════════════════════
// Initial Data Load
// ═══════════════════════════════════════════════════════════════

function loadInitialData() {
  Promise.all([
    fetch('/kpi').then(r => r.json()),
    fetch('/sessions/recent?limit=25').then(r => r.json())
  ]).then(([kpi, recent]) => {
    updateDashboard(kpi, recent);
  }).catch(err => console.error('Load error:', err));
}

// ═══════════════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initAllCharts();
  if (typeof initAttackMap === 'function') {
    initAttackMap();
  }
  initFilters();
  applyTranslations();
  loadInitialData();
  initWebSocket();
});
