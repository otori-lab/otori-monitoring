/**
 * OTORI Dashboard - Modal System
 * IP detail modal and generic detail modal
 */

// ═══════════════════════════════════════════════════════════════
// IP Detail Modal
// ═══════════════════════════════════════════════════════════════

function openIpModal(ip) {
  if (!ip || ip === '-') return;

  const modal = document.getElementById('ip-modal');
  modal.classList.add('open');
  document.body.style.overflow = 'hidden';

  fetch(`/ips/${encodeURIComponent(ip)}/details`)
    .then(r => r.json())
    .then(data => {
      if (data.sessions && data.sessions.length > 0) {
        populateIpModalFromApi(ip, data);
      } else {
        const ipSessions = allSessions.filter(s => s.src_ip === ip);
        populateIpModal(ip, ipSessions);
      }
    })
    .catch(() => {
      const ipSessions = allSessions.filter(s => s.src_ip === ip);
      populateIpModal(ip, ipSessions);
    });
}

function closeIpModal(event) {
  if (event && event.target !== event.currentTarget) return;
  const modal = document.getElementById('ip-modal');
  modal.classList.remove('open');
  document.body.style.overflow = '';
}

function filterByModalIP() {
  const ip = document.getElementById('modal-ip').textContent;
  closeIpModal();

  const sessionsBtn = document.querySelector('.nav-btn[data-page="sessions"]');
  if (sessionsBtn && !sessionsBtn.classList.contains('active')) {
    sessionsBtn.click();
  }

  document.getElementById('filter-ip').value = ip;
  activeFilters.ip = ip;
  saveFilters();
  applyFilters();
  renderFilteredSessions();
  updateFilterSummary();
}

function populateIpModalFromApi(ip, data) {
  document.getElementById('modal-ip').textContent = ip;
  document.getElementById('modal-flag').textContent = countryCodeToFlag(data.geo?.country_code);
  document.getElementById('modal-country-name').textContent = data.geo?.country_name || data.geo?.country_code || 'Unknown';

  document.getElementById('modal-sessions-count').textContent = data.stats.total_sessions;
  document.getElementById('modal-commands-count').textContent = data.stats.total_commands;
  document.getElementById('modal-avg-score').textContent = data.stats.avg_danger_score;
  document.getElementById('modal-avg-score').style.color =
    data.stats.avg_danger_score >= 80 ? 'var(--red)' : data.stats.avg_danger_score >= 50 ? 'var(--orange)' : data.stats.avg_danger_score >= 25 ? 'var(--yellow)' : 'var(--green)';

  const totalDuration = data.sessions.reduce((sum, s) => sum + (s.duration_sec || 0), 0);
  document.getElementById('modal-total-duration').textContent = fmtDuration(totalDuration);
  document.getElementById('modal-usernames-count').textContent = data.stats.unique_usernames;

  const maxDanger = Math.max(...Object.values(data.danger_distribution), 1);
  const dangerDistHtml = ['critical', 'high', 'medium', 'low', 'minimal'].map(level => `
    <div class="danger-bar-row">
      <span class="danger-bar-label ${level}">${level}</span>
      <div class="danger-bar-track">
        <div class="danger-bar-fill ${level}" style="width: ${(data.danger_distribution[level] / maxDanger) * 100}%"></div>
      </div>
      <span class="danger-bar-value">${data.danger_distribution[level]}</span>
    </div>
  `).join('');
  document.getElementById('modal-danger-distribution').innerHTML = dangerDistHtml;

  const attackerTypes = {};
  data.sessions.forEach(s => {
    const type = s.attacker_type || 'unknown';
    attackerTypes[type] = (attackerTypes[type] || 0) + 1;
  });
  const dominantAttacker = Object.entries(attackerTypes).sort((a, b) => b[1] - a[1])[0];

  const honeypotTypes = { classic: 0, ia: 0 };
  data.sessions.forEach(s => {
    if (s.honeypot_type === 'ia') honeypotTypes.ia++;
    else honeypotTypes.classic++;
  });

  const hasPersistence = data.sessions.some(s => s.categories_seen?.includes('persist'));
  const hasCredential = data.sessions.some(s => s.categories_seen?.includes('credential'));

  const attackProfileHtml = `
    <div style="display: flex; flex-direction: column; gap: 12px;">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span style="color: var(--muted); font-size: 12px;">${t('modal.attackerType')}</span>
        <span class="attacker-badge ${dominantAttacker ? dominantAttacker[0] : 'unknown'}">${dominantAttacker ? dominantAttacker[0] : 'unknown'}</span>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span style="color: var(--muted); font-size: 12px;">${t('modal.honeypotType')}</span>
        <span style="font-size: 13px; font-weight: 600;">${honeypotTypes.ia > honeypotTypes.classic ? 'IA' : 'Classic'} (${Math.max(honeypotTypes.ia, honeypotTypes.classic)})</span>
      </div>
      <div style="display: flex; gap: 12px; margin-top: 8px;">
        <span class="filter-badge ${hasPersistence ? 'high' : 'unchecked'}" style="cursor: default;">Persistence</span>
        <span class="filter-badge ${hasCredential ? 'critical' : 'unchecked'}" style="cursor: default;">Credential</span>
      </div>
    </div>
  `;
  document.getElementById('modal-attack-profile').innerHTML = attackProfileHtml;

  const sessionsListHtml = data.sessions.length === 0
    ? `<div class="empty-state">${t('empty.noSession')}</div>`
    : data.sessions.slice(0, 10).map(s => {
      const scoreClass = s.danger_score >= 80 ? 'critical' : s.danger_score >= 50 ? 'high' : s.danger_score >= 25 ? 'medium' : 'low';
      return `
        <div class="modal-session-item">
          <div class="modal-session-info">
            <div class="modal-session-user">${esc(s.username) || '-'}</div>
            <div class="modal-session-meta">${s.command_count || 0} cmds - ${fmtDuration(s.duration_sec)}</div>
          </div>
          <div class="modal-session-badges">
            <span class="score-wrapper">
              <span class="score-bar"><span class="score-bar-fill ${scoreClass}" style="width: ${s.danger_score || 0}%"></span></span>
              <span class="score-value">${s.danger_score || 0}</span>
            </span>
            <span class="danger-badge ${s.danger_level || 'unknown'}">${s.danger_level || 'unknown'}</span>
          </div>
        </div>
      `;
    }).join('');
  document.getElementById('modal-sessions-list').innerHTML = sessionsListHtml;

  if (data.top_commands && data.top_commands.length > 0) {
    const cmdHtml = data.top_commands.slice(0, 15).map(cmd => `
      <div class="modal-command-item" style="cursor: pointer;" onclick="closeIpModal(); showCommandDetails('${esc(cmd.command).replace(/'/g, "\\'")}')">
        <span class="severity-badge ${cmd.severity || 'info'}">${cmd.severity || 'info'}</span>
        <span class="modal-command-text">${esc(cmd.command)}</span>
        <span class="modal-command-count">x${cmd.count}</span>
      </div>
    `).join('');
    document.getElementById('modal-commands-list').innerHTML = cmdHtml;
  } else {
    document.getElementById('modal-commands-list').innerHTML = `<div class="empty-state" style="padding: 20px;">${t('modal.noCommands')}</div>`;
  }

  const usernames = [...new Set(data.sessions.map(s => s.username).filter(Boolean))];
  const usernamesHtml = usernames.slice(0, 20).map(u => `
    <span class="filter-badge bot" style="cursor: default;">${esc(u)}</span>
  `).join('') || `<span style="color: var(--muted);">-</span>`;
  document.getElementById('modal-usernames-list').innerHTML = usernamesHtml;
}

function populateIpModal(ip, sessions) {
  document.getElementById('modal-ip').textContent = ip;

  const countryCode = sessions[0]?.country_code || 'PRIVATE';
  document.getElementById('modal-flag').textContent = countryCodeToFlag(countryCode);
  document.getElementById('modal-country-name').textContent = countryCode;

  const totalSessions = sessions.length;
  const totalCommands = sessions.reduce((sum, s) => sum + (s.command_count || 0), 0);
  const avgScore = totalSessions > 0
    ? Math.round(sessions.reduce((sum, s) => sum + (s.danger_score || 0), 0) / totalSessions)
    : 0;
  const totalDuration = sessions.reduce((sum, s) => sum + (s.duration_sec || 0), 0);
  const uniqueUsernames = new Set(sessions.map(s => s.username).filter(Boolean));

  document.getElementById('modal-sessions-count').textContent = totalSessions;
  document.getElementById('modal-commands-count').textContent = totalCommands;
  document.getElementById('modal-avg-score').textContent = avgScore;
  document.getElementById('modal-avg-score').style.color =
    avgScore >= 80 ? 'var(--red)' : avgScore >= 50 ? 'var(--orange)' : avgScore >= 25 ? 'var(--yellow)' : 'var(--green)';
  document.getElementById('modal-total-duration').textContent = fmtDuration(totalDuration);
  document.getElementById('modal-usernames-count').textContent = uniqueUsernames.size;

  const dangerCounts = { critical: 0, high: 0, medium: 0, low: 0, minimal: 0 };
  sessions.forEach(s => {
    const level = s.danger_level || 'minimal';
    if (dangerCounts[level] !== undefined) dangerCounts[level]++;
  });

  const maxDanger = Math.max(...Object.values(dangerCounts), 1);
  const dangerDistHtml = ['critical', 'high', 'medium', 'low', 'minimal'].map(level => `
    <div class="danger-bar-row">
      <span class="danger-bar-label ${level}">${level}</span>
      <div class="danger-bar-track">
        <div class="danger-bar-fill ${level}" style="width: ${(dangerCounts[level] / maxDanger) * 100}%"></div>
      </div>
      <span class="danger-bar-value">${dangerCounts[level]}</span>
    </div>
  `).join('');
  document.getElementById('modal-danger-distribution').innerHTML = dangerDistHtml;

  document.getElementById('modal-attack-profile').innerHTML = '<div class="empty-state">-</div>';

  const sessionsListHtml = sessions.length === 0
    ? `<div class="empty-state">${t('empty.noSession')}</div>`
    : sessions.slice(0, 10).map(s => {
      const scoreClass = s.danger_score >= 80 ? 'critical' : s.danger_score >= 50 ? 'high' : s.danger_score >= 25 ? 'medium' : 'low';
      return `
        <div class="modal-session-item">
          <div class="modal-session-info">
            <div class="modal-session-user">${esc(s.username) || '-'}</div>
            <div class="modal-session-meta">${s.command_count || 0} cmds - ${fmtDuration(s.duration_sec)}</div>
          </div>
          <div class="modal-session-badges">
            <span class="score-wrapper">
              <span class="score-bar"><span class="score-bar-fill ${scoreClass}" style="width: ${s.danger_score || 0}%"></span></span>
              <span class="score-value">${s.danger_score || 0}</span>
            </span>
            <span class="danger-badge ${s.danger_level || 'unknown'}">${s.danger_level || 'unknown'}</span>
          </div>
        </div>
      `;
    }).join('');
  document.getElementById('modal-sessions-list').innerHTML = sessionsListHtml;

  fetchIpCommands(ip);

  const usernamesHtml = Array.from(uniqueUsernames).slice(0, 20).map(u => `
    <span class="filter-badge bot" style="cursor: default;">${esc(u)}</span>
  `).join('') || `<span style="color: var(--muted);">-</span>`;
  document.getElementById('modal-usernames-list').innerHTML = usernamesHtml;
}

function fetchIpCommands(ip) {
  fetch(`/commands/by-ip/${encodeURIComponent(ip)}?limit=20`)
    .then(r => {
      if (!r.ok) throw new Error('Not found');
      return r.json();
    })
    .then(commands => {
      renderModalCommands(commands);
    })
    .catch(() => {
      document.getElementById('modal-commands-list').innerHTML = `
        <div class="empty-state" style="padding: 20px;">${t('modal.noCommands')}</div>
      `;
    });
}

function renderModalCommands(commands) {
  const container = document.getElementById('modal-commands-list');
  if (!commands || commands.length === 0) {
    container.innerHTML = `<div class="empty-state" style="padding: 20px;">${t('modal.noCommands')}</div>`;
    return;
  }

  const cmdCounts = {};
  commands.forEach(cmd => {
    const text = cmd.command || cmd.input || '';
    if (text) {
      cmdCounts[text] = (cmdCounts[text] || 0) + 1;
    }
  });

  const sorted = Object.entries(cmdCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15);

  container.innerHTML = sorted.map(([cmd, count]) => `
    <div class="modal-command-item" style="cursor: pointer;" onclick="closeIpModal(); showCommandDetails('${esc(cmd.substring(0, 80)).replace(/'/g, "\\'")}')">
      <span class="severity-badge ${getSeverityForCommand(cmd)}">${getSeverityForCommand(cmd)}</span>
      <span class="modal-command-text">${esc(cmd.substring(0, 80))}${cmd.length > 80 ? '...' : ''}</span>
      <span class="modal-command-count">x${count}</span>
    </div>
  `).join('');
}

// ═══════════════════════════════════════════════════════════════
// Generic Detail Modal
// ═══════════════════════════════════════════════════════════════

function openDetailModal(title, iconClass, fetchFn) {
  const modal = document.getElementById('detail-modal');
  const titleEl = document.getElementById('detail-modal-title-text');
  const iconEl = document.getElementById('detail-modal-icon');
  const body = document.getElementById('detail-modal-body');

  titleEl.textContent = title;
  iconEl.className = 'icon ' + iconClass;
  body.innerHTML = `<div class="detail-modal-loading">${t('detail.loading')}</div>`;

  modal.classList.add('open');
  document.body.style.overflow = 'hidden';

  fetchFn().then(html => {
    body.innerHTML = html;
  }).catch(err => {
    body.innerHTML = `<div class="empty-state">${t('detail.noResults')}</div>`;
  });
}

function closeDetailModal(event) {
  if (event && event.target !== event.currentTarget) return;
  const modal = document.getElementById('detail-modal');
  modal.classList.remove('open');
  if (!document.getElementById('ip-modal').classList.contains('open')) {
    document.body.style.overflow = '';
  }
}

// Close modals on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeDetailModal();
    closeIpModal();
  }
});
