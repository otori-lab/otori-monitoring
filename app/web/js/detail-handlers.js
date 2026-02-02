/**
 * OTORI Dashboard - Detail Modal Handlers
 * Functions that populate the generic detail modal with specific content
 */

// ═══════════════════════════════════════════════════════════════
// Auth Details (Success/Failed)
// ═══════════════════════════════════════════════════════════════
function showAuthDetails(authType) {
  const isSuccess = authType === 'success';
  const title = isSuccess ? t('detail.authSuccess') : t('detail.authFailed');
  const iconClass = isSuccess ? 'auth-success' : 'auth-failed';
  const icon = isSuccess ? '✓' : '✗';

  document.getElementById('detail-modal-icon').textContent = icon;

  openDetailModal(title, iconClass, async () => {
    const response = await fetch(`/auth/details?auth_type=${authType}&limit=100`);
    const events = await response.json();

    if (!events.length) {
      return `<div class="empty-state">${t('detail.noResults')}</div>`;
    }

    const ipGroups = {};
    events.forEach(e => {
      if (!ipGroups[e.src_ip]) {
        ipGroups[e.src_ip] = {
          ip: e.src_ip,
          country_code: e.country_code,
          count: 0,
          usernames: new Set(),
          passwords: new Set(),
          events: []
        };
      }
      ipGroups[e.src_ip].count++;
      if (e.username) ipGroups[e.src_ip].usernames.add(e.username);
      if (e.password) ipGroups[e.src_ip].passwords.add(e.password);
      if (ipGroups[e.src_ip].events.length < 5) {
        ipGroups[e.src_ip].events.push(e);
      }
    });

    const sortedIps = Object.values(ipGroups).sort((a, b) => b.count - a.count);
    const uniqueUsers = new Set(events.map(e => e.username).filter(Boolean));
    const uniquePwds = new Set(events.map(e => e.password).filter(Boolean));

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--${isSuccess ? 'green' : 'red'})">${events.length}</div>
          <div class="label">${t('detail.totalEvents')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${sortedIps.length}</div>
          <div class="label">${t('detail.uniqueIps')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--purple)">${uniqueUsers.size}</div>
          <div class="label">${t('modal.usernames')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--orange)">${uniquePwds.size}</div>
          <div class="label">${t('auth.passwords')}</div>
        </div>
      </div>
      <div class="detail-section-title">IPs (${sortedIps.length})</div>
      <div class="detail-list">
    `;

    sortedIps.slice(0, 30).forEach(ipData => {
      const flag = countryCodeToFlag(ipData.country_code);
      html += `
        <div class="detail-item">
          <span class="flag" style="font-size: 20px;">${flag}</span>
          <div class="detail-item-main">
            <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(ipData.ip)}')">${esc(ipData.ip)}</div>
            <div class="detail-item-meta">
              <span>${ipData.usernames.size} username(s)</span>
              <span>${ipData.passwords.size} password(s)</span>
            </div>
          </div>
          <div class="detail-item-count">${ipData.count}x</div>
        </div>
      `;
    });

    html += '</div>';
    return html;
  });
}

// ═══════════════════════════════════════════════════════════════
// Command Search (by command text)
// ═══════════════════════════════════════════════════════════════
function showCommandDetails(command) {
  document.getElementById('detail-modal-icon').textContent = '>';

  openDetailModal(t('detail.commandSearch'), 'command', async () => {
    const response = await fetch(`/commands/search?q=${encodeURIComponent(command)}&limit=100`);
    const data = await response.json();

    if (!data.ips || !data.ips.length) {
      return `<div class="empty-state">${t('detail.noResults')}</div>`;
    }

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--accent)">${data.total_executions}</div>
          <div class="label">${t('detail.executions')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${data.unique_ips}</div>
          <div class="label">${t('detail.uniqueIps')}</div>
        </div>
      </div>
      <div class="modal-card" style="margin-bottom: 16px; padding: 12px;">
        <code style="font-family: 'JetBrains Mono', monospace; font-size: 12px; word-break: break-all;">${esc(data.query)}</code>
      </div>
      <div class="detail-section-title">IPs qui ont execute cette commande</div>
      <div class="detail-list">
    `;

    data.ips.forEach(ipData => {
      const flag = countryCodeToFlag(ipData.country_code);
      html += `
        <div class="detail-item">
          <span class="flag" style="font-size: 20px;">${flag}</span>
          <div class="detail-item-main">
            <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(ipData.ip)}')">${esc(ipData.ip)}</div>
            <div class="detail-item-meta">
              <span>Premier: ${new Date(ipData.first_seen * 1000).toLocaleString()}</span>
              <span>Dernier: ${new Date(ipData.last_seen * 1000).toLocaleString()}</span>
            </div>
          </div>
          <div class="detail-item-count">${ipData.count}x</div>
        </div>
      `;
    });

    html += '</div>';
    return html;
  });
}

// ═══════════════════════════════════════════════════════════════
// Category Commands
// ═══════════════════════════════════════════════════════════════
function showCategoryDetails(category) {
  document.getElementById('detail-modal-icon').textContent = '◆';

  openDetailModal(`${t('detail.categoryCommands')}: ${category}`, 'category', async () => {
    const response = await fetch(`/commands/by-category/${encodeURIComponent(category)}?limit=100`);
    const data = await response.json();

    if (!data.commands || !data.commands.length) {
      return `<div class="empty-state">${t('detail.noResults')}</div>`;
    }

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--purple)">${data.total_commands}</div>
          <div class="label">${t('detail.totalEvents')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${data.unique_commands}</div>
          <div class="label">Commandes uniques</div>
        </div>
      </div>
      <div class="detail-section-title">Commandes</div>
      <div class="detail-list">
    `;

    data.commands.forEach(cmd => {
      html += `
        <div class="detail-item" style="cursor: pointer;" onclick="showCommandDetails('${esc(cmd.command.replace(/'/g, "\\'"))}')">
          <span class="severity-badge ${cmd.severity || 'info'}">${cmd.severity || 'info'}</span>
          <div class="detail-item-main">
            <div class="detail-item-title">${esc(cmd.command)}</div>
            <div class="detail-item-meta">
              <span>${cmd.unique_ips} IP(s)</span>
              ${cmd.mitre_techniques?.length ? `<span>MITRE: ${cmd.mitre_techniques.join(', ')}</span>` : ''}
            </div>
          </div>
          <div class="detail-item-count">${cmd.count}x</div>
        </div>
      `;
    });

    html += '</div>';
    return html;
  });
}

// ═══════════════════════════════════════════════════════════════
// Severity Commands
// ═══════════════════════════════════════════════════════════════
function showSeverityDetails(severity) {
  document.getElementById('detail-modal-icon').textContent = '!';

  openDetailModal(`${t('detail.severityCommands')}: ${severity}`, 'severity', async () => {
    const response = await fetch(`/commands/by-severity/${encodeURIComponent(severity)}?limit=100`);
    const data = await response.json();

    if (!data.commands || !data.commands.length) {
      return `<div class="empty-state">${t('detail.noResults')}</div>`;
    }

    const colorMap = { critical: 'red', high: 'orange', medium: 'yellow', low: 'green', info: 'muted' };

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--${colorMap[severity] || 'muted'})">${data.total_commands}</div>
          <div class="label">${t('detail.totalEvents')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${data.unique_commands}</div>
          <div class="label">Commandes uniques</div>
        </div>
      </div>
      <div class="detail-section-title">Commandes ${severity}</div>
      <div class="detail-list">
    `;

    data.commands.forEach(cmd => {
      html += `
        <div class="detail-item" style="cursor: pointer;" onclick="showCommandDetails('${esc(cmd.command.replace(/'/g, "\\'"))}')">
          <span class="danger-badge ${cmd.category || 'unknown'}" style="font-size: 9px; padding: 4px 8px;">${cmd.category || '?'}</span>
          <div class="detail-item-main">
            <div class="detail-item-title">${esc(cmd.command)}</div>
            <div class="detail-item-meta">
              <span>${cmd.unique_ips} IP(s)</span>
            </div>
          </div>
          <div class="detail-item-count">${cmd.count}x</div>
        </div>
      `;
    });

    html += '</div>';
    return html;
  });
}

// ═══════════════════════════════════════════════════════════════
// Country Sessions
// ═══════════════════════════════════════════════════════════════
function showCountryDetails(countryCode, countryName) {
  document.getElementById('detail-modal-icon').textContent = countryCodeToFlag(countryCode);

  openDetailModal(`${t('detail.countryDetails')}: ${countryName || countryCode}`, 'country', async () => {
    const response = await fetch(`/sessions/by-country/${encodeURIComponent(countryCode)}?limit=50`);
    const sessions = await response.json();

    if (!sessions.length) {
      return `<div class="empty-state">${t('detail.noResults')}</div>`;
    }

    const uniqueIps = new Set(sessions.map(s => s.src_ip));
    const totalCmds = sessions.reduce((sum, s) => sum + (s.command_count || 0), 0);
    const avgScore = Math.round(sessions.reduce((sum, s) => sum + (s.danger_score || 0), 0) / sessions.length);

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--accent)">${sessions.length}</div>
          <div class="label">${t('modal.sessions')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${uniqueIps.size}</div>
          <div class="label">${t('detail.uniqueIps')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--purple)">${totalCmds}</div>
          <div class="label">${t('modal.commands')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--${avgScore >= 50 ? 'red' : avgScore >= 25 ? 'orange' : 'green'})">${avgScore}</div>
          <div class="label">${t('modal.avgScore')}</div>
        </div>
      </div>
      <div class="detail-section-title">Sessions</div>
      <div class="detail-list">
    `;

    sessions.forEach(s => {
      html += `
        <div class="detail-item">
          <div class="detail-item-main">
            <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(s.src_ip)}')">${esc(s.src_ip)}</div>
            <div class="detail-item-meta">
              <span>${esc(s.username) || '-'}</span>
              <span>${s.command_count} cmds</span>
              <span>${fmtDuration(s.duration_sec)}</span>
            </div>
          </div>
          <div class="detail-item-badges">
            <span class="danger-badge ${s.danger_level || 'unknown'}">${s.danger_level || '?'}</span>
            <span class="score-value">${s.danger_score || 0}</span>
          </div>
        </div>
      `;
    });

    html += '</div>';
    return html;
  });
}

// ═══════════════════════════════════════════════════════════════
// Password Details
// ═══════════════════════════════════════════════════════════════
function showPasswordDetails(password) {
  document.getElementById('detail-modal-icon').textContent = '🔑';

  openDetailModal(t('detail.passwordAttempts'), 'auth-failed', async () => {
    const response = await fetch(`/auth/details?auth_type=all&limit=200`);
    const events = await response.json();
    const filtered = events.filter(e => e.password === password);

    if (!filtered.length) {
      return `<div class="empty-state">${t('detail.noResults')}</div>`;
    }

    const uniqueIps = new Set(filtered.map(e => e.src_ip));
    const successCount = filtered.filter(e => e.event_type === 'login_success').length;

    let html = `
      <div class="modal-card" style="margin-bottom: 16px; padding: 12px;">
        <code style="font-family: 'JetBrains Mono', monospace; font-size: 14px;">${esc(password)}</code>
      </div>
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--accent)">${filtered.length}</div>
          <div class="label">Tentatives</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${uniqueIps.size}</div>
          <div class="label">${t('detail.uniqueIps')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--green)">${successCount}</div>
          <div class="label">${t('auth.success')}</div>
        </div>
      </div>
      <div class="detail-section-title">IPs</div>
      <div class="detail-list">
    `;

    const ipCounts = {};
    filtered.forEach(e => {
      ipCounts[e.src_ip] = (ipCounts[e.src_ip] || 0) + 1;
    });

    Object.entries(ipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .forEach(([ip, count]) => {
        const event = filtered.find(e => e.src_ip === ip);
        const flag = countryCodeToFlag(event?.country_code);
        html += `
          <div class="detail-item">
            <span class="flag" style="font-size: 20px;">${flag}</span>
            <div class="detail-item-main">
              <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(ip)}')">${esc(ip)}</div>
            </div>
            <div class="detail-item-count">${count}x</div>
          </div>
        `;
      });

    html += '</div>';
    return html;
  });
}

// ═══════════════════════════════════════════════════════════════
// MITRE Technique Details
// ═══════════════════════════════════════════════════════════════
function showMitreDetails(techniqueId, techniqueName) {
  document.getElementById('detail-modal-icon').textContent = '⚔';

  openDetailModal(`${t('detail.mitreTechnique')}: ${techniqueId}`, 'mitre', async () => {
    let html = `
      <div class="modal-card" style="margin-bottom: 16px; padding: 16px;">
        <div style="font-size: 18px; font-weight: 700; color: var(--yellow);">${techniqueId}</div>
        <div style="font-size: 14px; color: var(--text); margin-top: 8px;">${techniqueName || 'Unknown technique'}</div>
        <a href="https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/" target="_blank"
           style="display: inline-block; margin-top: 12px; color: var(--blue); font-size: 12px;">
          Voir sur MITRE ATT&CK →
        </a>
      </div>
      <div class="empty-state" style="padding: 20px;">
        Les commandes associees a cette technique seront affichees ici.
      </div>
    `;

    return html;
  });
}

// ═══════════════════════════════════════════════════════════════
// KPI Card Click Handlers
// ═══════════════════════════════════════════════════════════════

function showAllSessions() {
  document.getElementById('detail-modal-icon').textContent = '📊';

  openDetailModal('Toutes les Sessions', 'auth-success', async () => {
    if (!allSessions.length) {
      return `<div class="empty-state">${t('detail.noResults')}</div>`;
    }

    const uniqueIps = new Set(allSessions.map(s => s.src_ip));
    const totalCmds = allSessions.reduce((sum, s) => sum + (s.command_count || 0), 0);

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--accent)">${allSessions.length}</div>
          <div class="label">${t('modal.sessions')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${uniqueIps.size}</div>
          <div class="label">${t('detail.uniqueIps')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--purple)">${totalCmds}</div>
          <div class="label">${t('modal.commands')}</div>
        </div>
      </div>
      <div class="detail-section-title">Sessions recentes</div>
      <div class="detail-list">
    `;

    allSessions.slice(0, 30).forEach(s => {
      const flag = countryCodeToFlag(s.country_code);
      html += `
        <div class="detail-item">
          <span class="flag" style="font-size: 18px;">${flag}</span>
          <div class="detail-item-main">
            <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(s.src_ip)}')">${esc(s.src_ip)}</div>
            <div class="detail-item-meta">
              <span>${esc(s.username) || '-'}</span>
              <span>${s.command_count || 0} cmds</span>
              <span>${fmtDuration(s.duration_sec)}</span>
            </div>
          </div>
          <div class="detail-item-badges">
            <span class="danger-badge ${s.danger_level || 'unknown'}">${s.danger_level || '?'}</span>
          </div>
        </div>
      `;
    });

    html += '</div>';
    return html;
  });
}

function showTopIpsModal() {
  document.getElementById('detail-modal-icon').textContent = '🌐';

  openDetailModal('Top IPs Attaquantes', 'command', async () => {
    const ipCounts = {};
    allSessions.forEach(s => {
      if (!ipCounts[s.src_ip]) {
        ipCounts[s.src_ip] = {
          ip: s.src_ip,
          country_code: s.country_code,
          sessions: 0,
          commands: 0,
          maxScore: 0
        };
      }
      ipCounts[s.src_ip].sessions++;
      ipCounts[s.src_ip].commands += s.command_count || 0;
      ipCounts[s.src_ip].maxScore = Math.max(ipCounts[s.src_ip].maxScore, s.danger_score || 0);
    });

    const sorted = Object.values(ipCounts).sort((a, b) => b.sessions - a.sessions);

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${sorted.length}</div>
          <div class="label">${t('detail.uniqueIps')}</div>
        </div>
      </div>
      <div class="detail-section-title">IPs par nombre de sessions</div>
      <div class="detail-list">
    `;

    sorted.slice(0, 30).forEach((ipData, i) => {
      const flag = countryCodeToFlag(ipData.country_code);
      const scoreClass = ipData.maxScore >= 80 ? 'critical' : ipData.maxScore >= 50 ? 'high' : ipData.maxScore >= 25 ? 'medium' : 'low';
      html += `
        <div class="detail-item">
          <span class="rank ${i < 3 ? 'top3' : ''}" style="width: 24px; height: 24px; font-size: 11px;">${i + 1}</span>
          <span class="flag" style="font-size: 18px;">${flag}</span>
          <div class="detail-item-main">
            <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(ipData.ip)}')">${esc(ipData.ip)}</div>
            <div class="detail-item-meta">
              <span>${ipData.sessions} session(s)</span>
              <span>${ipData.commands} cmd(s)</span>
            </div>
          </div>
          <span class="danger-badge ${scoreClass}">${ipData.maxScore}</span>
        </div>
      `;
    });

    html += '</div>';
    return html;
  });
}

function showTopCommandsModal() {
  document.getElementById('detail-modal-icon').textContent = '>';

  openDetailModal('Top Commandes', 'command', async () => {
    let html = `
      <div class="detail-section-title">Commandes frequentes</div>
      <div class="detail-list">
    `;

    if (cachedKpi?.top_commands) {
      cachedKpi.top_commands.slice(0, 20).forEach(cmd => {
        html += `
          <div class="detail-item" style="cursor: pointer;" onclick="showCommandDetails('${esc(cmd.command || '').replace(/'/g, "\\'")}')">
            <div class="detail-item-main">
              <div class="detail-item-title" style="font-family: 'JetBrains Mono', monospace;">${esc((cmd.command || '').substring(0, 60))}</div>
            </div>
            <div class="detail-item-count">${cmd.count}x</div>
          </div>
        `;
      });
    } else {
      html += `<div class="empty-state">${t('detail.noResults')}</div>`;
    }

    html += '</div>';
    return html;
  });
}

function showSessionsByDuration() {
  document.getElementById('detail-modal-icon').textContent = '⏱';

  openDetailModal('Sessions par Duree', 'auth-success', async () => {
    const sorted = [...allSessions].sort((a, b) => (b.duration_sec || 0) - (a.duration_sec || 0));

    const avgDuration = allSessions.length > 0
      ? allSessions.reduce((sum, s) => sum + (s.duration_sec || 0), 0) / allSessions.length
      : 0;

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--green)">${fmtDuration(avgDuration)}</div>
          <div class="label">Duree moyenne</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--accent)">${fmtDuration(sorted[0]?.duration_sec || 0)}</div>
          <div class="label">Plus longue</div>
        </div>
      </div>
      <div class="detail-section-title">Sessions triees par duree</div>
      <div class="detail-list">
    `;

    sorted.slice(0, 30).forEach(s => {
      const flag = countryCodeToFlag(s.country_code);
      html += `
        <div class="detail-item">
          <span class="flag" style="font-size: 18px;">${flag}</span>
          <div class="detail-item-main">
            <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(s.src_ip)}')">${esc(s.src_ip)}</div>
            <div class="detail-item-meta">
              <span>${esc(s.username) || '-'}</span>
              <span>${s.command_count || 0} cmds</span>
            </div>
          </div>
          <div class="detail-item-count" style="color: var(--green);">${fmtDuration(s.duration_sec)}</div>
        </div>
      `;
    });

    html += '</div>';
    return html;
  });
}

function showHighDangerSessions() {
  document.getElementById('detail-modal-icon').textContent = '⚠';

  openDetailModal('Sessions Danger Eleve', 'severity', async () => {
    const highDanger = allSessions.filter(s =>
      s.danger_level === 'critical' || s.danger_level === 'high'
    ).sort((a, b) => (b.danger_score || 0) - (a.danger_score || 0));

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--red)">${highDanger.filter(s => s.danger_level === 'critical').length}</div>
          <div class="label">Critical</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--orange)">${highDanger.filter(s => s.danger_level === 'high').length}</div>
          <div class="label">High</div>
        </div>
      </div>
      <div class="detail-section-title">Sessions a risque eleve</div>
      <div class="detail-list">
    `;

    highDanger.slice(0, 30).forEach(s => {
      const flag = countryCodeToFlag(s.country_code);
      html += `
        <div class="detail-item">
          <span class="flag" style="font-size: 18px;">${flag}</span>
          <div class="detail-item-main">
            <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(s.src_ip)}')">${esc(s.src_ip)}</div>
            <div class="detail-item-meta">
              <span>${esc(s.username) || '-'}</span>
              <span>${s.command_count || 0} cmds</span>
            </div>
          </div>
          <div class="detail-item-badges">
            <span class="danger-badge ${s.danger_level}">${s.danger_level}</span>
            <span class="score-value">${s.danger_score || 0}</span>
          </div>
        </div>
      `;
    });

    if (highDanger.length === 0) {
      html += `<div class="empty-state">${t('detail.noResults')}</div>`;
    }

    html += '</div>';
    return html;
  });
}

function showAllMitreTechniques() {
  document.getElementById('detail-modal-icon').textContent = '⚔';

  openDetailModal('Techniques MITRE ATT&CK', 'mitre', async () => {
    const response = await fetch('/mitre/techniques');
    const data = await response.json();

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--yellow)">${data.total_unique || 0}</div>
          <div class="label">Techniques uniques</div>
        </div>
      </div>
      <div class="detail-section-title">Techniques detectees</div>
      <div class="detail-list">
    `;

    if (data.techniques) {
      data.techniques.forEach(tech => {
        html += `
          <div class="detail-item" style="cursor: pointer;" onclick="showMitreDetails('${tech.technique_id}', '${esc(tech.technique_name)}')">
            <span class="severity-badge medium" style="min-width: 70px;">${tech.technique_id}</span>
            <div class="detail-item-main">
              <div class="detail-item-title">${esc(tech.technique_name)}</div>
              <div class="detail-item-meta">
                <span>Tactic: ${tech.tactic || 'Unknown'}</span>
              </div>
            </div>
            <div class="detail-item-count">${tech.count}x</div>
          </div>
        `;
      });
    }

    html += '</div>';
    return html;
  });
}

function showAttackerTypeDetails() {
  document.getElementById('detail-modal-icon').textContent = '🤖';

  openDetailModal('Types d\'Attaquants', 'category', async () => {
    const bots = allSessions.filter(s => s.attacker_type === 'bot');
    const humans = allSessions.filter(s => s.attacker_type === 'human');
    const hybrid = allSessions.filter(s => s.attacker_type === 'hybrid');
    const unknown = allSessions.filter(s => !s.attacker_type || s.attacker_type === 'unknown');

    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--purple)">${bots.length}</div>
          <div class="label">Bots</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${humans.length}</div>
          <div class="label">Humans</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--yellow)">${hybrid.length}</div>
          <div class="label">Hybrid</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--muted)">${unknown.length}</div>
          <div class="label">Unknown</div>
        </div>
      </div>
    `;

    if (bots.length > 0) {
      html += `<div class="detail-section-title">Sessions Bot (${bots.length})</div><div class="detail-list">`;
      bots.slice(0, 10).forEach(s => {
        const flag = countryCodeToFlag(s.country_code);
        html += `
          <div class="detail-item">
            <span class="flag" style="font-size: 18px;">${flag}</span>
            <div class="detail-item-main">
              <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(s.src_ip)}')">${esc(s.src_ip)}</div>
              <div class="detail-item-meta"><span>${s.command_count || 0} cmds</span></div>
            </div>
            <span class="attacker-badge bot">bot</span>
          </div>
        `;
      });
      html += '</div>';
    }

    if (humans.length > 0) {
      html += `<div class="detail-section-title">Sessions Human (${humans.length})</div><div class="detail-list">`;
      humans.slice(0, 10).forEach(s => {
        const flag = countryCodeToFlag(s.country_code);
        html += `
          <div class="detail-item">
            <span class="flag" style="font-size: 18px;">${flag}</span>
            <div class="detail-item-main">
              <div class="detail-item-title clickable" onclick="closeDetailModal(); openIpModal('${esc(s.src_ip)}')">${esc(s.src_ip)}</div>
              <div class="detail-item-meta"><span>${s.command_count || 0} cmds</span></div>
            </div>
            <span class="attacker-badge human">human</span>
          </div>
        `;
      });
      html += '</div>';
    }

    return html;
  });
}

function showTimelineDetails(label, sessionCount, commandCount) {
  document.getElementById('detail-modal-icon').textContent = '📈';

  openDetailModal(`Activite: ${label}`, 'command', async () => {
    let html = `
      <div class="detail-stats">
        <div class="detail-stat">
          <div class="value" style="color: var(--accent)">${sessionCount}</div>
          <div class="label">${t('modal.sessions')}</div>
        </div>
        <div class="detail-stat">
          <div class="value" style="color: var(--blue)">${commandCount}</div>
          <div class="label">${t('modal.commands')}</div>
        </div>
      </div>
      <div class="modal-card" style="padding: 16px; text-align: center;">
        <div style="font-size: 14px; color: var(--muted);">Periode selectionnee</div>
        <div style="font-size: 20px; font-weight: 700; margin-top: 8px;">${label}</div>
      </div>
      <div style="margin-top: 20px; padding: 20px; background: var(--panel2); border-radius: var(--radius-sm); text-align: center;">
        <p style="color: var(--muted); margin-bottom: 12px;">Pour voir les sessions de cette periode, utilisez les filtres sur la page Sessions.</p>
        <button class="btn-secondary" onclick="closeDetailModal(); document.querySelector('.nav-btn[data-page=sessions]').click();">
          Aller aux Sessions
        </button>
      </div>
    `;
    return html;
  });
}
